#!/usr/bin/env python3  

import argparse
from sys import exit
import dns.resolver
from dns.resolver import NoAnswer, NoNameservers, NXDOMAIN  # exceptions
from dns.rdatatype import UnknownRdatatype                  # exceptions


class APIError(ValueError):
    pass


def get_records(args):
    resolver = dns.resolver.Resolver()
    if args.nameservers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = args.nameservers
    try:
        if not args.record:
            answers = resolver.query(args.domain)
        elif args.record == 'dmarc'.lower():
            target = f'_dmarc.{args.domain.lower()}'
            answers = resolver.query(target, 'TXT')
        else:
            answers = resolver.query(args.domain, args.record)
        print(f'{answers.rrset.__str__()}')
    except (NoAnswer, UnknownRdatatype, NoNameservers) as e:
        raise APIError() from e


def main():
    parser = argparse.ArgumentParser(
        prog='dnslookup',
        description='Pull DNS records for a given domain',
    )
    parser.add_argument('domain', help='domain name to look up')
    parser.add_argument('--record', help='record type to look up: \'A\', \'MX\', etc.')
    parser.add_argument('--nameservers', nargs='+', help='nameservers used to query records')
    args = parser.parse_args()
    try:
        get_records(args)
    except APIError as e:
        exit(e.__cause__)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        # from pdb import post_mortem
        # post_mortem()
        print(f'Error: {e}')
