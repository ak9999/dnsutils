"""Tests for the dnslookup module."""

from __future__ import annotations

import argparse
import logging
import sys
from unittest import mock

import pytest
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers
from dns.rdatatype import UnknownRdatatype

from dnsutils._logging import configure_logging
from dnsutils.dnslookup import get_records, main
from dnsutils.exceptions import (
    DomainNotFoundError,
    InvalidRecordTypeError,
    NoNameserversError,
    NoRecordsError,
    TimeoutError as DNSTimeoutError,
)


class MockAnswer:
    """Mock DNS answer object."""

    def __init__(self, rrset_str: str = "example.com. 300 IN A 192.0.2.1") -> None:
        self.rrset = type("RRset", (), {"__str__": lambda _: rrset_str})()


# Tests for get_records()


def test_get_records_default(capsys) -> None:
    """Test default lookup (no record type specified)."""
    args = argparse.Namespace(domain="example.com", record=None, nameservers=None)
    mock_answer = MockAnswer()

    with mock.patch("dns.resolver.Resolver.resolve", return_value=mock_answer):
        get_records(args)
        captured = capsys.readouterr()
        assert "example.com. 300 IN A 192.0.2.1" in captured.out


def test_get_records_a_record(capsys) -> None:
    """Test lookup for A record."""
    args = argparse.Namespace(domain="example.com", record="A", nameservers=None)
    mock_answer = MockAnswer()

    with mock.patch("dns.resolver.Resolver.resolve", return_value=mock_answer):
        get_records(args)
        captured = capsys.readouterr()
        assert "example.com. 300 IN A 192.0.2.1" in captured.out


def test_get_records_mx_record(capsys) -> None:
    """Test lookup for MX record."""
    args = argparse.Namespace(domain="example.com", record="MX", nameservers=None)
    mock_answer = MockAnswer("example.com. 3600 IN MX 10 mail.example.com.")

    with mock.patch("dns.resolver.Resolver.resolve", return_value=mock_answer):
        get_records(args)
        captured = capsys.readouterr()
        assert "MX" in captured.out


def test_get_records_txt_record(capsys) -> None:
    """Test lookup for TXT record."""
    args = argparse.Namespace(domain="example.com", record="TXT", nameservers=None)
    mock_answer = MockAnswer('example.com. 300 IN TXT "v=spf1 -all"')

    with mock.patch("dns.resolver.Resolver.resolve", return_value=mock_answer):
        get_records(args)
        captured = capsys.readouterr()
        assert "TXT" in captured.out


def test_get_records_aaaa_record(capsys) -> None:
    """Test lookup for AAAA (IPv6) record."""
    args = argparse.Namespace(domain="example.com", record="AAAA", nameservers=None)
    mock_answer = MockAnswer("example.com. 300 IN AAAA 2001:db8::1")

    with mock.patch("dns.resolver.Resolver.resolve", return_value=mock_answer):
        get_records(args)
        captured = capsys.readouterr()
        assert "AAAA" in captured.out


def test_get_records_dmarc(capsys) -> None:
    """Test lookup for DMARC pseudo-type."""
    args = argparse.Namespace(domain="example.com", record="dmarc", nameservers=None)
    mock_answer = MockAnswer('_dmarc.example.com. 3600 IN TXT "v=DMARC1; p=none"')

    with mock.patch(
        "dns.resolver.Resolver.resolve", return_value=mock_answer
    ) as mock_resolve:
        get_records(args)
        # Verify it resolves the DMARC target with TXT
        mock_resolve.assert_called_once_with("_dmarc.example.com", "TXT")
        captured = capsys.readouterr()
        assert "DMARC1" in captured.out


def test_get_records_custom_nameservers() -> None:
    """Test lookup with custom nameservers."""
    args = argparse.Namespace(
        domain="example.com",
        record="A",
        nameservers=["8.8.8.8", "1.1.1.1"],
    )
    mock_answer = MockAnswer()

    with mock.patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_instance = mock_resolver_class.return_value
        mock_instance.resolve.return_value = mock_answer

        with mock.patch("dnsutils.dnslookup.logger"):
            get_records(args)

        # Verify resolver was created without default config
        calls = mock_resolver_class.call_args_list
        assert any(call[1].get("configure") is False for call in calls), (
            "Resolver should be created with configure=False when nameservers are provided"
        )


def test_get_records_nxdomain() -> None:
    """Test that NXDOMAIN exception raises DomainNotFoundError."""
    args = argparse.Namespace(
        domain="nonexistent.invalid", record=None, nameservers=None
    )

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NXDOMAIN()):
        with pytest.raises(DomainNotFoundError) as exc_info:
            get_records(args)
        assert exc_info.value.domain == "nonexistent.invalid"
        assert exc_info.value.record_type is None


def test_get_records_no_answer() -> None:
    """Test that NoAnswer exception raises NoRecordsError."""
    args = argparse.Namespace(domain="example.com", record="AAAA", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NoAnswer()):
        with pytest.raises(NoRecordsError) as exc_info:
            get_records(args)
        assert exc_info.value.domain == "example.com"
        assert exc_info.value.record_type == "AAAA"


def test_get_records_unknown_rdatatype() -> None:
    """Test that UnknownRdatatype exception raises InvalidRecordTypeError."""
    args = argparse.Namespace(domain="example.com", record="INVALID", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=UnknownRdatatype()):
        with pytest.raises(InvalidRecordTypeError) as exc_info:
            get_records(args)
        assert exc_info.value.domain == "example.com"
        assert exc_info.value.record_type == "INVALID"


def test_get_records_no_nameservers() -> None:
    """Test that NoNameservers exception raises NoNameserversError."""
    args = argparse.Namespace(domain="example.com", record=None, nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NoNameservers()):
        with pytest.raises(NoNameserversError) as exc_info:
            get_records(args)
        assert exc_info.value.domain == "example.com"


def test_get_records_timeout() -> None:
    """Test that Timeout exception raises DNSTimeoutError."""
    args = argparse.Namespace(domain="example.com", record=None, nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=Timeout()):
        with pytest.raises(DNSTimeoutError) as exc_info:
            get_records(args)
        assert exc_info.value.domain == "example.com"


# Tests for main()


def test_main_success(capsys) -> None:
    """Test main() succeeds with valid arguments."""
    mock_answer = MockAnswer()

    with mock.patch.object(sys, "argv", ["dnslookup", "example.com"]):
        with mock.patch("dns.resolver.Resolver.resolve", return_value=mock_answer):
            main()
            captured = capsys.readouterr()
            assert "example.com. 300 IN A 192.0.2.1" in captured.out


def test_main_error_logs_to_stderr(caplog) -> None:
    """Test main() logs error to stderr on DNS lookup failure."""
    with mock.patch.object(sys, "argv", ["dnslookup", "nonexistent.invalid"]):
        with mock.patch(
            "dns.resolver.Resolver.resolve",
            side_effect=NXDOMAIN("DNS name not found"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "nonexistent.invalid" in caplog.text


def test_main_with_record_type(capsys) -> None:
    """Test main() with --record argument."""
    mock_answer = MockAnswer("example.com. 3600 IN MX 10 mail.example.com.")

    with mock.patch.object(sys, "argv", ["dnslookup", "example.com", "--record", "MX"]):
        with mock.patch("dns.resolver.Resolver.resolve", return_value=mock_answer):
            main()
            captured = capsys.readouterr()
            assert "MX" in captured.out


def test_main_with_custom_nameservers() -> None:
    """Test main() with --nameservers argument."""
    mock_answer = MockAnswer()

    with mock.patch.object(
        sys,
        "argv",
        ["dnslookup", "example.com", "--nameservers", "8.8.8.8", "1.1.1.1"],
    ):
        with mock.patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_instance = mock_resolver_class.return_value
            mock_instance.resolve.return_value = mock_answer

            with mock.patch("dnsutils.dnslookup.logger"):
                main()

            # Verify nameservers were set
            calls = mock_resolver_class.call_args_list
            assert any(call[1].get("configure") is False for call in calls), (
                "Resolver should be created with configure=False when nameservers are provided"
            )


def test_main_dmarc_lookup(capsys) -> None:
    """Test main() with DMARC pseudo-type."""
    mock_answer = MockAnswer('_dmarc.example.com. 3600 IN TXT "v=DMARC1; p=none"')

    with mock.patch.object(
        sys, "argv", ["dnslookup", "example.com", "--record", "dmarc"]
    ):
        with mock.patch(
            "dns.resolver.Resolver.resolve", return_value=mock_answer
        ) as mock_resolve:
            main()
            mock_resolve.assert_called_with("_dmarc.example.com", "TXT")
            captured = capsys.readouterr()
            assert "DMARC1" in captured.out


def test_dnslookup_error_preserves_original_exception() -> None:
    """Test that DNSLookupError preserves original exception and context."""
    args = argparse.Namespace(domain="example.com", record=None, nameservers=None)
    original_error = NXDOMAIN("The DNS query name does not exist")

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=original_error):
        with pytest.raises(DomainNotFoundError) as exc_info:
            get_records(args)
        # Check that original exception is preserved
        assert exc_info.value.original_exception is original_error
        assert exc_info.value.__cause__ is original_error
        # Check context attributes
        assert exc_info.value.domain == "example.com"
        assert exc_info.value.record_type is None
        # Check formatted message
        assert "example.com" in str(exc_info.value)


# Tests for logging configuration


def test_main_no_records_error(caplog) -> None:
    """Test main() logs error on NoRecordsError."""
    with mock.patch.object(sys, "argv", ["dnslookup", "example.com"]):
        with mock.patch(
            "dns.resolver.Resolver.resolve",
            side_effect=NoAnswer(),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "example.com" in caplog.text


def test_main_invalid_record_type(caplog) -> None:
    """Test main() logs error on InvalidRecordTypeError."""
    with mock.patch.object(sys, "argv", ["dnslookup", "example.com", "--record", "INVALID"]):
        with mock.patch(
            "dns.resolver.Resolver.resolve",
            side_effect=UnknownRdatatype(),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "INVALID" in caplog.text


def test_main_timeout_error(caplog) -> None:
    """Test main() logs error on DNSTimeoutError."""
    with mock.patch.object(sys, "argv", ["dnslookup", "example.com"]):
        with mock.patch(
            "dns.resolver.Resolver.resolve",
            side_effect=Timeout(),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "timeout" in caplog.text.lower()


def test_main_no_nameservers_error(caplog) -> None:
    """Test main() logs error on NoNameserversError."""
    with mock.patch.object(sys, "argv", ["dnslookup", "example.com"]):
        with mock.patch(
            "dns.resolver.Resolver.resolve",
            side_effect=NoNameservers(),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "nameservers" in caplog.text


def test_configure_logging() -> None:
    """Test that logging is configured correctly."""
    logger = logging.getLogger("dnsutils")

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    configure_logging(logging.DEBUG)

    # Check logger has handlers
    assert len(logger.handlers) > 0

    # Check handler has correct level and formatter
    handler = logger.handlers[0]
    assert handler.level == logging.DEBUG
    formatter = handler.formatter
    assert formatter is not None
    assert formatter._fmt is not None
    assert "asctime" in formatter._fmt


def test_configure_logging_idempotent() -> None:
    """Test that configure_logging is idempotent (doesn't duplicate handlers)."""
    logger = logging.getLogger("dnsutils")

    # Clear handlers first
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    configure_logging(logging.INFO)
    initial_handler_count = len(logger.handlers)

    # Call again
    configure_logging(logging.INFO)

    # Should not add more handlers
    assert len(logger.handlers) == initial_handler_count
