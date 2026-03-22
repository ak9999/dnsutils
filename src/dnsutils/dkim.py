#!/usr/bin/env python3
"""DKIM (DomainKeys Identified Mail) validator for DNS records."""

import argparse
import logging
import sys

import dns.resolver

from dnsutils._dns_utils import resolve_dns_records
from dnsutils.exceptions import (
    DNSLookupError,
    DomainNotFoundError,
    DKIMRecordNotFoundError,
    NoRecordsError,
    TimeoutError as DNSTimeoutError,
)

logger = logging.getLogger(__name__)


def parse_dkim_record(record: str) -> dict[str, str]:
    """Parse DKIM record into structured format.

    Args:
        record: The DKIM record string.

    Returns:
        Dictionary containing parsed DKIM tags.
    """
    parsed = {}
    parts = record.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            parsed[key.strip()] = value.strip()

    return parsed


def _find_dkim_record(answers: dns.resolver.Answer) -> str:
    """Find DKIM record among TXT records.

    Args:
        answers: DNS Answer object containing TXT records.

    Returns:
        DKIM record string.

    Raises:
        DKIMRecordNotFoundError: If no DKIM record found.
    """
    for rdata in answers:
        for txt_string in rdata.strings:
            text = txt_string.decode() if isinstance(txt_string, bytes) else txt_string
            if "v=DKIM1" in text:
                return text
    raise DKIMRecordNotFoundError(
        "No valid DKIM record found",
        record_type="DKIM",
    )


def get_dkim(args: argparse.Namespace) -> None:
    """Retrieve and display DKIM record for a domain.

    Args:
        args: Parsed command-line arguments containing domain, selector, and
            optional nameservers.

    Raises:
        DNSLookupError: If the DKIM lookup fails.
    """
    dkim_target = f"{args.selector}._domainkey.{args.domain}"
    answers = resolve_dns_records(args.domain, "TXT", args.nameservers, dkim_target)
    dkim_record = _find_dkim_record(answers)

    # Parse and display DKIM record
    parsed = parse_dkim_record(dkim_record)
    print(f"DKIM Record: {dkim_record}")
    print(f"Version: {parsed.get('v', 'unknown')}")
    if "k" in parsed:
        print(f"Key Type: {parsed['k']}")
    if "h" in parsed:
        print(f"Hash Algorithm: {parsed['h']}")
    if "p" in parsed:
        key_preview = parsed["p"][:50] + "..." if len(parsed["p"]) > 50 else parsed["p"]
        print(f"Public Key: {key_preview}")


def main() -> None:
    """Parse arguments and look up DKIM record.

    Exits with code 1 if DKIM lookup fails.
    """
    parser = argparse.ArgumentParser(
        prog="dkim",
        description="Retrieve and analyze DKIM record for a domain",
    )
    parser.add_argument("domain", help="domain name to check DKIM for")
    parser.add_argument("selector", help="DKIM selector (e.g., 'default', 'google')")
    parser.add_argument(
        "--nameservers", nargs="+", help="nameservers used to query records"
    )
    args: argparse.Namespace = parser.parse_args()
    try:
        get_dkim(args)
    except DomainNotFoundError as e:
        # Distinguish between the main domain not existing vs. DKIM subdomain not existing
        if "_domainkey" in str(e):
            logger.error(
                f"No DKIM record found for '{args.domain}' with selector '{args.selector}'. "
                f"{args.selector}._domainkey.{args.domain} does not exist (DKIM not configured)"
            )
        else:
            logger.error(f"Domain '{args.domain}' does not exist")
        sys.exit(1)
    except NoRecordsError:
        logger.error(
            f"No DKIM record found for '{args.domain}' with selector '{args.selector}'. "
            f"The domain exists but has no TXT records at {args.selector}._domainkey.{args.domain}"
        )
        sys.exit(1)
    except DKIMRecordNotFoundError:
        logger.error(
            f"Domain '{args.domain}' has TXT records at {args.selector}._domainkey.{args.domain} "
            f"but no valid DKIM record. Check that it contains a record with 'v=DKIM1'"
        )
        sys.exit(1)
    except DNSTimeoutError:
        logger.error(
            f"DNS lookup timed out for '{args.domain}'. Try again later or specify different nameservers"
        )
        sys.exit(1)
    except DNSLookupError as e:
        logger.error(f"DNS lookup failed for '{args.domain}': {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
