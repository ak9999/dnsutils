"""Custom exceptions for DNS utilities."""


class DNSLookupError(Exception):
    """Base exception for DNS lookup failures.

    Attributes:
        domain: The domain that was being queried.
        record_type: The DNS record type that was requested (e.g., 'A', 'MX').
        original_exception: The underlying dnspython exception.
    """

    def __init__(
        self,
        message: str,
        domain: str | None = None,
        record_type: str | None = None,
        original_exception: Exception | None = None,
    ) -> None:
        """Initialize DNSLookupError.

        Args:
            message: Human-readable error message.
            domain: The domain that was being queried.
            record_type: The DNS record type requested.
            original_exception: The underlying exception from dnspython.
        """
        self.domain = domain
        self.record_type = record_type
        self.original_exception = original_exception
        super().__init__(message)


class DomainNotFoundError(DNSLookupError):
    """Raised when a domain does not exist (NXDOMAIN)."""

    pass


class NoRecordsError(DNSLookupError):
    """Raised when a domain exists but has no records of the requested type."""

    pass


class InvalidRecordTypeError(DNSLookupError):
    """Raised when an invalid DNS record type is specified."""

    pass


class TimeoutError(DNSLookupError):
    """Raised when DNS resolution times out."""

    pass


class NoNameserversError(DNSLookupError):
    """Raised when no nameservers are available."""

    pass


class SPFRecordNotFoundError(DNSLookupError):
    """Raised when SPF record is not found in TXT records."""

    pass


class DKIMRecordNotFoundError(DNSLookupError):
    """Raised when DKIM record is not found in TXT records."""

    pass


class DMARCRecordNotFoundError(DNSLookupError):
    """Raised when DMARC record is not found in TXT records."""

    pass
