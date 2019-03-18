"""
TODO: module docstring
"""


import argparse
from dns.resolver import query


def get_records(domain):
    answers = query(domain, 'TXT')
    print(f'Query qname: {answers.qname}\t Number of answers: {len(answers)}')
    for rdata in answers:
        for txt_string in rdata.strings:
            print(f'TXT: {txt_string}')


def main():
    parser = argparse.ArgumentParser(
        prog='DNS Parser',
        description='Pull DNS records for a given domain',
    )
    parser.add_argument('domain', default='google.com')
    args = parser.parse_args()
    get_records(args.domain)


if __name__ == '__main__':
    main()
