"""
TODO: add module docstring
"""

from dns.resolver import query

from pprint import pprint


def main():
    '''It just prints out info about TXT records hopefully.'''

    domain = 'ajkhan.me'
    txt_records = query(domain, 'TXT')

    pprint(txt_records.__dict__.keys())

    for record in txt_records:
        pprint(record)


main()
