#!/usr/bin/env python3
"""SPF (Sender Policy Framework) checker for DNS records."""

import argparse
import logging
import sys

import dns.resolver

from dnsutils._dns_utils import resolve_dns_records
from dnsutils.exceptions import (
    DNSLookupError,
    DomainNotFoundError,
    NoRecordsError,
    SPFRecordNotFoundError,
    TimeoutError as DNSTimeoutError,
)

logger = logging.getLogger(__name__)


def parse_spf_record(record: str) -> dict[str, str | list[str] | dict[str, str]]:
    """Parse SPF record into structured format.

    Args:
        record: The SPF record string.

    Returns:
        Dictionary containing parsed SPF components.
    """
    parts = record.split()
    parsed: dict = {"version": "", "mechanisms": [], "modifiers": {}}

    for part in parts:
        if part.startswith("v="):
            parsed["version"] = part.split("=", 1)[1]
        elif "=" in part:
            key, value = part.split("=", 1)
            parsed["modifiers"][key] = value
        else:
            parsed["mechanisms"].append(part)

    return parsed


def _find_spf_record(answers: dns.resolver.Answer) -> str:
    """Find SPF record among TXT records.

    Args:
        answers: DNS Answer object containing TXT records.

    Returns:
        SPF record string.

    Raises:
        SPFRecordNotFoundError: If no SPF record found.
    """
    for rdata in answers:
        for txt_string in rdata.strings:
            text = txt_string.decode() if isinstance(txt_string, bytes) else txt_string
            if text.startswith("v=spf1"):
                return text
    raise SPFRecordNotFoundError(
        "No SPF record found",
        record_type="SPF",
    )


def get_spf(args: argparse.Namespace) -> None:
    """Retrieve and display SPF record for a domain.

    Args:
        args: Parsed command-line arguments containing domain and optional
            nameservers.

    Raises:
        DNSLookupError: If the SPF lookup fails.
    """
    answers = resolve_dns_records(args.domain, "TXT", args.nameservers)
    spf_record = _find_spf_record(answers)

    # Parse and display SPF record
    parsed = parse_spf_record(spf_record)
    print(f"SPF Record: {spf_record}")
    print(
        f"Mechanisms: {', '.join(parsed['mechanisms']) if parsed['mechanisms'] else 'none'}"
    )
    if parsed["modifiers"]:
        print(f"Modifiers: {parsed['modifiers']}")


def main() -> None:
    """Parse arguments and look up SPF record.

    Exits with code 1 if SPF lookup fails.
    """
    parser = argparse.ArgumentParser(
        prog="spf",
        description="Retrieve and analyze SPF record for a domain",
    )
    parser.add_argument("domain", help="domain name to check SPF for")
    parser.add_argument(
        "--nameservers", nargs="+", help="nameservers used to query records"
    )
    args: argparse.Namespace = parser.parse_args()
    try:
        get_spf(args)
    except DomainNotFoundError:
        logger.error(
            f"No SPF record found for '{args.domain}'. "
            f"The domain exists but SPF records are not configured (NXDOMAIN on TXT query)"
        )
        sys.exit(1)
    except NoRecordsError:
        logger.error(
            f"No SPF record found for '{args.domain}'. "
            f"The domain exists but has no TXT records (SPF not configured)"
        )
        sys.exit(1)
    except SPFRecordNotFoundError:
        logger.error(
            f"Domain '{args.domain}' has TXT records but no valid SPF record. "
            f"Check that it contains a record starting with 'v=spf1'"
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
