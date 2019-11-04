#!/usr/bin/env python3  
"""
TODO: module docstring
"""

import argparse
from sys import exit
from dns.resolver import query
from dns.resolver import NoAnswer, NoNameservers, NXDOMAIN
from dns.rdatatype import UnknownRdatatype


class APIError(ValueError):
    pass


def get_records(domain, record_type):
    try:
        if record_type == 'dmarc'.lower():
            target = f'_dmarc.{domain.lower()}'
            answers = query(target, 'TXT')
            print(f'{answers.rrset.__str__()}')
        else:
            answers = query(domain, record_type)
            print(f'{answers.rrset.__str__()}')
    except (NoAnswer, UnknownRdatatype, NoNameservers) as e:
        raise APIError() from e


def main():
    parser = argparse.ArgumentParser(
        prog='recordslookup',
        description='Pull DNS records for a given domain',
    )
    parser.add_argument('domain')
    parser.add_argument('record_type')
    args = parser.parse_args()
    try:
        get_records(args.domain, args.record_type)
    except APIError as e:
        exit(e.__cause__)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        # from pdb import post_mortem
        # post_mortem()
        print(f'Error: {e}')
