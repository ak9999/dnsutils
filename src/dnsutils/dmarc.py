#!/usr/bin/env python3
"""DMARC (Domain-based Message Authentication, Reporting & Conformance) analyzer."""

import argparse
import logging
import sys

import dns.resolver

from dnsutils._dns_utils import resolve_dns_records
from dnsutils.exceptions import (
    DNSLookupError,
    DomainNotFoundError,
    DMARCRecordNotFoundError,
    NoRecordsError,
    TimeoutError as DNSTimeoutError,
)

logger = logging.getLogger(__name__)


def parse_dmarc_record(record: str) -> dict[str, str]:
    """Parse DMARC record into structured format.

    Args:
        record: The DMARC record string.

    Returns:
        Dictionary containing parsed DMARC tags.
    """
    parsed = {}
    parts = record.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            parsed[key.strip()] = value.strip()

    return parsed


def analyze_dmarc_policy(parsed: dict[str, str]) -> dict[str, str]:
    """Analyze DMARC policy and provide interpretation.

    Args:
        parsed: Parsed DMARC record dictionary.

    Returns:
        Dictionary containing policy analysis.
    """
    policy = parsed.get("p", "none")
    policy_strength_map = {
        "reject": "Strong (reject)",
        "quarantine": "Medium (quarantine)",
        "none": "Weak (none - monitoring only)",
    }

    analysis = {
        "version": parsed.get("v", "unknown"),
        "policy": policy,
        "subdomain_policy": parsed.get("sp", "inherit"),
        "alignment_dkim": parsed.get("adkim", "r"),
        "alignment_spf": parsed.get("aspf", "r"),
        "percentage": parsed.get("pct", "100"),
        "policy_strength": policy_strength_map.get(policy, "Unknown"),
    }

    return analysis


def _find_dmarc_record(answers: dns.resolver.Answer) -> str:
    """Find DMARC record among TXT records.

    Args:
        answers: DNS Answer object containing TXT records.

    Returns:
        DMARC record string.

    Raises:
        DMARCRecordNotFoundError: If no DMARC record found.
    """
    for rdata in answers:
        for txt_string in rdata.strings:
            text = txt_string.decode() if isinstance(txt_string, bytes) else txt_string
            if text.startswith("v=DMARC1"):
                return text
    raise DMARCRecordNotFoundError(
        "No valid DMARC record found",
        record_type="DMARC",
    )


def get_dmarc(args: argparse.Namespace) -> None:
    """Retrieve and display DMARC record for a domain.

    Args:
        args: Parsed command-line arguments containing domain and optional
            nameservers.

    Raises:
        DNSLookupError: If the DMARC lookup fails.
    """
    dmarc_target = f"_dmarc.{args.domain}"
    answers = resolve_dns_records(args.domain, "TXT", args.nameservers, dmarc_target)
    dmarc_record = _find_dmarc_record(answers)

    # Parse and analyze DMARC record
    parsed = parse_dmarc_record(dmarc_record)
    analysis = analyze_dmarc_policy(parsed)

    print(f"DMARC Record: {dmarc_record}")
    print(f"Version: {analysis['version']}")
    print(f"Policy: {analysis['policy']} ({analysis['policy_strength']})")
    print(f"DKIM Alignment: {analysis['alignment_dkim']}")
    print(f"SPF Alignment: {analysis['alignment_spf']}")
    print(f"Subdomain Policy: {analysis['subdomain_policy']}")
    print(f"Percentage: {analysis['percentage']}%")

    if "rua" in parsed:
        print(f"Aggregate Report URI: {parsed['rua']}")
    if "ruf" in parsed:
        print(f"Forensic Report URI: {parsed['ruf']}")


def main() -> None:
    """Parse arguments and look up DMARC record.

    Exits with code 1 if DMARC lookup fails.
    """
    parser = argparse.ArgumentParser(
        prog="dmarc",
        description="Retrieve and analyze DMARC record for a domain",
    )
    parser.add_argument("domain", help="domain name to check DMARC for")
    parser.add_argument(
        "--nameservers", nargs="+", help="nameservers used to query records"
    )
    args: argparse.Namespace = parser.parse_args()
    try:
        get_dmarc(args)
    except DomainNotFoundError as e:
        # Distinguish between the main domain not existing vs. DMARC subdomain not existing
        if "_dmarc" in str(e):
            logger.error(
                f"No DMARC record found for '{args.domain}'. "
                f"_dmarc.{args.domain} does not exist (DMARC not configured)"
            )
        else:
            logger.error(f"Domain '{args.domain}' does not exist")
        sys.exit(1)
    except NoRecordsError:
        logger.error(
            f"No DMARC record found for '{args.domain}'. "
            f"The domain exists but has no TXT records at _dmarc.{args.domain}"
        )
        sys.exit(1)
    except DMARCRecordNotFoundError:
        logger.error(
            f"Domain '{args.domain}' has TXT records but no valid DMARC record. "
            f"Check that _dmarc.{args.domain} contains a record starting with 'v=DMARC1'"
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
