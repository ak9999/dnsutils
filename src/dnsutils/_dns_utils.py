"""Shared DNS utilities for email authentication checkers."""

import dns.resolver
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers
from dns.rdatatype import UnknownRdatatype

from dnsutils.exceptions import (
    DomainNotFoundError,
    InvalidRecordTypeError,
    NoNameserversError,
    NoRecordsError,
    TimeoutError as DNSTimeoutError,
)


def resolve_dns_records(
    domain: str,
    record_type: str,
    nameservers: list[str] | None = None,
    query_target: str | None = None,
) -> dns.resolver.Answer:
    """Resolve DNS records with unified exception handling.

    Args:
        domain: Domain name being queried.
        record_type: DNS record type (e.g., 'TXT').
        nameservers: Optional list of nameservers to use.
        query_target: Actual DNS target to query (defaults to domain).

    Returns:
        Answer object from dnspython.

    Raises:
        DNSLookupError: On any DNS resolution failure.
    """
    resolver: dns.resolver.Resolver = dns.resolver.Resolver()
    if nameservers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = nameservers

    target: str = query_target or domain

    try:
        return resolver.resolve(target, record_type)
    except NXDOMAIN as e:
        raise DomainNotFoundError(
            f"Domain not found: {target}",
            domain=domain,
            record_type=record_type,
            original_exception=e,
        ) from e
    except NoAnswer as e:
        raise NoRecordsError(
            f"No {record_type} records found for {target}",
            domain=domain,
            record_type=record_type,
            original_exception=e,
        ) from e
    except UnknownRdatatype as e:
        raise InvalidRecordTypeError(
            f"Invalid record type: {record_type}",
            domain=domain,
            record_type=record_type,
            original_exception=e,
        ) from e
    except NoNameservers as e:
        raise NoNameserversError(
            "No nameservers available",
            domain=domain,
            record_type=record_type,
            original_exception=e,
        ) from e
    except Timeout as e:
        raise DNSTimeoutError(
            f"DNS resolution timeout for {target}",
            domain=domain,
            record_type=record_type,
            original_exception=e,
        ) from e
