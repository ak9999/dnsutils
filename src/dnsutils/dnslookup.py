#!/usr/bin/env python3
"""DNS lookup utility for retrieving DNS records for a given domain."""

import argparse
import logging
import sys
import dns.resolver
from dns.exception import Timeout
from dns.resolver import Answer, NXDOMAIN, NoAnswer, NoNameservers
from dns.rdatatype import UnknownRdatatype

from dnsutils.exceptions import (
    DNSLookupError,
    DomainNotFoundError,
    InvalidRecordTypeError,
    NoNameserversError,
    NoRecordsError,
    TimeoutError as DNSTimeoutError,
)

logger = logging.getLogger(__name__)


def get_records(args: argparse.Namespace) -> None:
    """Retrieve DNS records for a domain.

    Args:
        args: Parsed command-line arguments containing domain, record type,
            and optional nameservers.

    Raises:
        DNSLookupError: If the DNS lookup fails.
    """
    resolver: dns.resolver.Resolver = dns.resolver.Resolver()
    if args.nameservers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = args.nameservers
    try:
        if not args.record:
            answers: Answer = resolver.resolve(args.domain)
        elif args.record == "dmarc".lower():
            target: str = f"_dmarc.{args.domain.lower()}"
            answers = resolver.resolve(target, "TXT")
        else:
            answers = resolver.resolve(args.domain, args.record)
        print(answers.rrset)
    except NXDOMAIN as e:
        raise DomainNotFoundError(
            f"Domain not found: {args.domain}",
            domain=args.domain,
            record_type=args.record,
            original_exception=e,
        ) from e
    except NoAnswer as e:
        raise NoRecordsError(
            f"No {args.record or 'A'} records found for {args.domain}",
            domain=args.domain,
            record_type=args.record,
            original_exception=e,
        ) from e
    except UnknownRdatatype as e:
        raise InvalidRecordTypeError(
            f"Invalid record type: {args.record}",
            domain=args.domain,
            record_type=args.record,
            original_exception=e,
        ) from e
    except NoNameservers as e:
        raise NoNameserversError(
            "No nameservers available",
            domain=args.domain,
            record_type=args.record,
            original_exception=e,
        ) from e
    except Timeout as e:
        raise DNSTimeoutError(
            f"DNS resolution timeout for {args.domain}",
            domain=args.domain,
            record_type=args.record,
            original_exception=e,
        ) from e


def main() -> None:
    """Parse arguments and look up DNS records.

    Exits with code 1 if a DNS lookup error occurs.
    """
    parser = argparse.ArgumentParser(
        prog="dnslookup",
        description="Pull DNS records for a given domain",
    )
    parser.add_argument("domain", help="domain name to look up")
    parser.add_argument(
        "--record",
        help="record type to look up (e.g., 'A', 'MX', 'TXT', 'AAAA'). "
        "Omit to use default (A) records. Special pseudo-type 'dmarc' "
        "resolves _dmarc.<domain> TXT records.",
    )
    parser.add_argument(
        "--nameservers", nargs="+", help="nameservers used to query records"
    )
    args: argparse.Namespace = parser.parse_args()
    try:
        get_records(args)
    except DNSLookupError as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
