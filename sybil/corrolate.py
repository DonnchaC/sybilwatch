"""
Corrolate.py

Filter the Tor consensus to search for patterns in the consensus data
"""

import argparse
import datetime
import socket

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

    parser.add_argument("-d", "--data-dir", type=str, default=None,
                        help="Tor's data directory.", required=True)

    parser.add_argument("--tor-version", type=str, default=None,
                        help="Match Tor relay version (e.g. 0.2.6.0-alpha-dev")

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

    # Load cached descriptors from disk
    cached_descriptors = consensus.get_descriptors(args.data_dir)

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

    # Iterate and display matching relays
    headers = ['Address', 'OR', 'Dir', 'AS', 'Version',
               'Uptime', 'Fingerprint', 'Nickname']
    results = []

    for desc in descriptors:

        # Get AS info for IP
        try:
            whois = ipwhois.IPWhois(desc.address)
        except Exception:
            autonomous_system = None
        else:
            res = whois.lookup()
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
