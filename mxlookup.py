"""
TODO: add module docstring
"""

from dns.resolver import query
from pprint import pprint


def main():
    '''It just prints out info about MX records hopefully.'''

    domain = 'ajkhan.me'
    mx_records = query(domain, 'MX')

    pprint(mx_records.__dict__.keys())

    for record in mx_records:
        pprint(record)


main()
