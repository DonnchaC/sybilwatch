"""
Corrolate.py

Filter the Tor consensus to search for patterns in the consensus data
"""

import argparse
import datetime
import socket
import sys

import stem.control
import stem.descriptor
import ipwhois
import tabulate

import consensus
import log

logger = log.get_logger()


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--control-port", type=int, default=9051,
                        help="Tor's control port.")

    parser.add_argument("--tor-version", type=str, default=None,
                        help="Match Tor version (e.g. 0.2.6.0-alpha-dev)")

    parser.add_argument("--ips", type=argparse.FileType('r'), default=None,
                        help="Load list of IP's to filter the consensus.")

    parser.add_argument("--or-port", type=int, help="Filter by OR port.")

    parser.add_argument("--dir-port", type=int, help="Filter by Dir port.")

    args = parser.parse_args()

    if args.ips:
        args.ips = [ip.rstrip() for ip in args.ips]

    return args


def main():
    args = parse_cmd_args()

    controller = stem.control.Controller.from_port(port=args.control_port)
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
    if args.ips:
        descriptors = [desc for desc in descriptors if
                       desc.address in args.ips]
    if args.tor_version:
        descriptors = [desc for desc in descriptors if
                       str(desc.tor_version) == args.tor_version]
    if args.or_port:
        descriptors = [desc for desc in descriptors if
                       desc.or_port == args.or_port]
    if args.dir_port:
        descriptors = [desc for desc in descriptors if
                       desc.dir_port == args.dir_port]

    # Sort relays by IP address and OR port
    descriptors = sorted(descriptors,
                         key=lambda desc: (socket.inet_aton(desc.address),
                                           desc.or_port))

    logger.debug("Filter matched %s relays" % len(descriptors))

    # Iterate and display matching relays
    headers = ['Address', 'OR', 'Dir', 'AS', 'Version',
               'Uptime', 'Fingerprint', 'Nickname']
    results = []

    for desc in descriptors:

        # Get AS info for IP
        try:
            whois = ipwhois.IPWhois(desc.address)
            res = whois.lookup()
        except Exception:
            autonomous_system = None
        else:
            autonomous_system = '{} ({})'.format(
                res.get('asn'),
                res.get('nets')[0].get('name')
            )

        results.append([desc.address,
                        desc.or_port,
                        desc.dir_port,
                        autonomous_system,
                        str(desc.tor_version),
                        str(datetime.timedelta(seconds=desc.uptime)),
                        desc.fingerprint,
                        desc.nickname])

    print(tabulate.tabulate(results, headers))


if __name__ == "__main__":
    main()
