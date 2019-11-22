#!/usr/bin/env python3  

import argparse
from sys import exit
import dns.resolver
from dns.resolver import NoAnswer, NoNameservers, NXDOMAIN  # exceptions
from dns.rdatatype import UnknownRdatatype                  # exceptions


class APIError(ValueError):
    pass


def get_records(arguments):
    domain, record_type = arguments.domain, arguments.record_type
    resolver = dns.resolver.Resolver()
    if arguments.nameservers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = arguments.nameservers
    try:
        if record_type == 'dmarc'.lower():
            target = f'_dmarc.{domain.lower()}'
            answers = resolver.query(target, 'TXT')
            print(f'{answers.rrset.__str__()}')
        else:
            answers = resolver.query(domain, record_type)
            print(f'{answers.rrset.__str__()}')
    except (NoAnswer, UnknownRdatatype, NoNameservers) as e:
        raise APIError() from e


def main():
    parser = argparse.ArgumentParser(
        prog='dnslookup',
        description='Pull DNS records for a given domain',
    )
    parser.add_argument('domain', help='domain name to look up')
    parser.add_argument('record_type', help='record type to look up: \'A\', \'MX\', etc.')
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
