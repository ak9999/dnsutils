#!/usr/bin/env python3  
"""
TODO: module docstring
"""

import logging
import argparse
from dns.resolver import query


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_records(domain, record_type):
    answers = query(domain, record_type)
    print(f'DNS query for: {answers.qname}')
    try:
        print(f'{answers.rrset.__str__()}')
    except Exception as e:
        logger.exception(e)
        logger.info(e)


def main():
    parser = argparse.ArgumentParser(
        prog='recordslookup',
        description='Pull DNS records for a given domain',
    )
    parser.add_argument('domain')
    parser.add_argument('record_type')
    args = parser.parse_args()
    get_records(args.domain, args.record_type)


if __name__ == '__main__':
    main()
