# -*- coding: utf-8 -*-
"""
Corrolate.py

Filter the Tor consensus to search for patterns in the consensus data

TODO:
Allow filtering by all fields.
Searching by flags.
Allow searching of cached_descriptors as well as the cached_consensus
"""

import argparse
import datetime
import socket
import sys
import re
import csv
import collections
import itertools

import stem.control
import stem.descriptor
import pygeoip
import tabulate
import pytimeparse

import consensus
import log

logger = log.get_logger()


def comma_delimitated(string):
    return [value.strip() for value in string.split(',')]


def field_eval(field, value, statement, substitute_variables=True):
    """
    Simple conditional queries.
    """

    # Compare value against comma separated set of possibilities, return true
    # if any of provided values match

    values = comma_delimitated(statement)
    if len(values) > 1:
        #
        return any([v == str(value) for v in values])
    if field in statement and substitute_variables:
        return eval(statement.replace(field, str(value)))
    else:
        return statement == value


def get_autonomous_system(gi, ip_address, full=False):
    """
    Read autonomous system from local MaxMind DB
    """
    try:
        as_data = gi.org_by_addr(ip_address)
        as_number, organisation_name = as_data.split(' ', 1)
    except Exception:
        return None
    else:
        if full:
            return '{} {}'.format(as_number, organisation_name)
        else:
            return as_number


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser()

    parser.add_argument("-ip", "--control-ip", type=str, default='127.0.0.1',
                        help="Tor control port host (default: %(default)s)")

    parser.add_argument("-p", "--control-port", type=int, default=9051,
                        help="Tor control port (default: %(default)d)")

    maxmind = parser.add_argument_group('MaxMind GeoIP Options',
                                        description="Configure local MaxMind "
                                        "GeoIP database for AS lookups")

    maxmind.add_argument("--maxmind-download", action='store_true',
                         help="Download MaxMind AS file to current directory")

    maxmind.add_argument("--maxmind", type=str, default="GeoIPASNum.dat",
                         help="Location of MaxMind ISP database for AS lookup"
                              " (default: %(default)s)")

    filter = parser.add_argument_group('Relay Filter Options')

    filter.add_argument("--fingerprint-file", type=argparse.FileType('r'),
                        default=None)

    filter.add_argument("--ip-file", type=argparse.FileType('r'),
                        default=None)

    evald = parser.add_argument_group(
        description="These fields can be filtered by an expression with the "
        "field name. Example --or-port='9000', --or-port='or_port > 9000', "
        "--bandwidth='bandwidth > 10000 and bandwidth < 20000' or "
        "--bandwidth='10000,20000'")

    evald.add_argument("--bandwidth", type=str, default=None,
                       help="Relay average bandwidth")

    evald.add_argument("--or-port", type=str, help="Filter by OR port.")

    evald.add_argument("--dir-port", type=str, help="Filter by Dir port.")

    evald.add_argument("--asn", type=str, default=None, help="Filter by AS")

    filter.add_argument("--uptime-min", type=str, help="e.g. 10 days")

    filter.add_argument("--uptime-max", type=str, help="e.g. 15 days")

    filter.add_argument("--tor-version", type=str, default=None,
                        help="Match Tor version (e.g. 0.2.6.0-alpha-dev)")

    filter.add_argument("--nickname", type=str,
                        help="Filter nickname field with regex")

    filter.add_argument("--contact", type=str,
                        help="Filter contact field with regex")

    filter.add_argument("--no-contact", action='store_true',
                        help="Only show relays without contact field")

    output = parser.add_argument_group('Output Format')

    output.add_argument("--fingerprints", action='store_true',
                        help="Output list of fingerprints")

    output.add_argument("--ips", action='store_true',
                        help="Output list of IP's")

    output.add_argument("--fields", type=comma_delimitated,
                        default='address,or_port,dir_port,as,tor_version,'
                                'uptime,fingerprint',
                        help="Comma deliminated set of fields to display "
                             "(default '%(default)s'). Use as_full to get "
                             "the full AS name")

    output.add_argument("--format", choices=['simple', 'html', 'csv'],
                        default='simple')

    output.add_argument("--counter", type=comma_delimitated, default=[],
                        help="Output a table of frequency table for the "
                             "specified fields. (e.g. 'as,tor_version')")

    return parser.parse_args()


def download_maxmind():
    """
    Download MaxMind AS database and decompress to current directory
    """
    import requests
    import io
    import gzip
    response = requests.get(
        "http://download.maxmind.com/download/geoip/database/"
        "asnum/GeoIPASNum.dat.gz")
    compressed_file = io.BytesIO(response.content)
    decompressed_file = gzip.GzipFile(fileobj=compressed_file)

    with open("GeoIPASNum.dat", 'w') as outfile:
        outfile.write(decompressed_file.read())


def main():
    args = parse_cmd_args()

    # Download MaxMind AS database if requested
    if args.maxmind_download:
        logger.info("Beginning download of MaxMind AS database")
        download_maxmind()
        logger.info("Maxmind AS database downloaded to current directory")
        sys.exit(0)

    # Try open the local Maxmind database or skip AS lookups
    try:
        gi = pygeoip.GeoIP(args.maxmind, pygeoip.MEMORY_CACHE)
    except IOError:
        # Should actually check if it is a FileNotFound error
        logger.error("Could not find Maxmind file at '%s'. Try running "
                     "with --maxmind-download option. Skipping AS lookups"
                     % args.maxmind)
    else:
        logger.debug("Loaded MaxMind AS database")

    # Connect to Tor control port
    controller = stem.control.Controller.from_port(address=args.control_ip,
                                                   port=args.control_port)
    try:
        controller.authenticate()
    except stem.connection.AuthenticationFailure as exc:
        logger.error("Unable to authenticate to Tor control port: %s"
                     % exc)
        sys.exit(1)
    else:
        logger.debug("Successfully connected to the Tor control port")

    # Load cached descriptors from disk
    cached_descriptors = consensus.get_descriptors(controller)

    logger.debug("Finished loading Tor relay descriptors")

    # Filter the cached descriptors
    descriptors = cached_descriptors.values()

    # Filter by IP's or Fingerprints loaded from file
    if args.fingerprint_file:
        fingerprints = [fpr.rstrip() for fpr in args.fingerprint_file]

        descriptors = [desc for desc in descriptors if
                       desc.fingerprint in fingerprints]
    if args.ip_file:
        ips = [fpr.rstrip() for fpr in args.ip_file]
        descriptors = [desc for desc in descriptors if
                       desc.address in ips]

    if args.tor_version:
        descriptors = [desc for desc in descriptors if
                       str(desc.tor_version).startswith(args.tor_version)]

    # Regex Fields
    if args.no_contact:
        descriptors = [desc for desc in descriptors if
                       not desc.contact]
    elif args.contact:
        descriptors = [desc for desc in descriptors if
                       re.search(args.contact, str(desc.contact).strip())]
    if args.nickname:
        descriptors = [desc for desc in descriptors if
                       re.search(args.nickname, str(desc.nickname).strip())]

    # Fields which can be evaluated
    if args.or_port:
        descriptors = [desc for desc in descriptors if
                       field_eval('or_port', desc.or_port, args.or_port)]
    if args.dir_port:
        descriptors = [desc for desc in descriptors if
                       field_eval('dir_port', desc.dir_port, args.dir_port)]
    if args.bandwidth:
        descriptors = [desc for desc in descriptors if
                       field_eval('bandwidth', desc.average_bandwidth,
                                  args.bandwidth)]

    # Uptime fields, parse human-readable query
    if args.uptime_min:
        uptime_min = pytimeparse.parse(args.uptime_min)
        if uptime_min:
            descriptors = [desc for desc in descriptors if
                           desc.uptime >= uptime_min]
    if args.uptime_max:
        uptime_max = pytimeparse.parse(args.uptime_max)
        if uptime_max:
            descriptors = [desc for desc in descriptors if
                           desc.uptime <= uptime_max]

    # Sort relays by IP address and OR port
    descriptors = sorted(descriptors,
                         key=lambda desc: (socket.inet_aton(desc.address),
                                           desc.or_port))

    logger.debug("Filters matched %s relays" % len(descriptors))

    # Done filtering, now format the output
    if args.fingerprints:
        print('\n'.join(desc.fingerprint for desc in descriptors))
        sys.exit(0)

    if args.ips:
        print('\n'.join(sorted(set(desc.address for desc in descriptors),
                               key=lambda ip: (socket.inet_aton(ip)))))
        sys.exit(0)

    # Map user specified fields to descriptor attributes
    field_map = {
        'bandwidth': 'average_bandwidth',
        'version': 'tor_version'
    }
    fields = [field_map.get(f) if field_map.get(f) else f
              for f in args.fields]

    counter_fields = [field_map.get(f) if field_map.get(f) else f
                      for f in args.counter]

    # Combined fields for main results and counted data
    combined_fields = set(fields).union(set(counter_fields))

    # Iterate and prepare final relay info structure
    results = []
    for descriptor in descriptors:

        # Extract attributes for fields matching the specified output fields
        desc = {name: getattr(descriptor, name) if
                getattr(descriptor, name, None) else None for name in
                combined_fields}

        # Convert uptime to human readable if being tabulated
        if desc.get('uptime') and args.format != 'csv':
            desc['uptime'] = datetime.timedelta(seconds=desc.get('uptime'))

        # Determine AS if requested
        as_full = True if 'as_full' in fields else False
        if args.asn or ('as' in fields) or as_full:
            desc['as'] = get_autonomous_system(gi, descriptor.address,
                                               full=as_full)

        # Late stage filter by AS
            if args.asn:
                # Skip relay, if as doesn't match filter
                if not field_eval('as', desc['as'], args.asn, False):
                    continue

        results.append(desc)

    logger.debug('Prepared final relay info, outputting now!')

    # Output tabulated data
    if args.format in ['simple', 'html']:
        # Hmm, why doesn't a generator function of a generator function work?
        order_result_rows = [[row.get(f) for f in fields] for row in results]
        print(tabulate.tabulate(order_result_rows, fields,
                                tablefmt=args.format))

    # Output data in CSV format
    elif args.format == 'csv':
        writer = csv.DictWriter(sys.stdout, fieldnames=fields,
                                extrasaction='ignore')
        writer.writeheader()
        for result in results:
            writer.writerow(result)

    # If counter fields specified. Create a frequency count for data values
    if args.counter:
        # Create counter object for each defined counter field
        counters = {field: collections.Counter() for field in counter_fields}

        # Iterate counter fields in user specified order
        output_columns = []
        for field in counter_fields:
            # Update counter if field value exists for this result
            counters[field].update([result.get(field) for result in results
                                    if result.get(field)])

            # Get list of final (key, count) from the Counter() object
            key_count_pairs = [(value, count) for value, count
                               in counters[field].items()]
            # Sort pairs by count
            key_count_pairs.sort(key=lambda pair: pair[1], reverse=True)
            output_columns.extend(zip(*key_count_pairs))
        result_rows = itertools.izip_longest(*output_columns)

        # Create list of headers, followed by empty field for the count column
        column_headers = sum(([field, ''] for field in counter_fields), [])

        print('')
        print(tabulate.tabulate(result_rows,
                                headers=column_headers,
                                tablefmt=args.format))

    logger.debug('Output complete. Finished!')
    sys.exit(0)


if __name__ == "__main__":
    main()
