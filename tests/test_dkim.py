"""Tests for the dkim module."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Iterator, cast
from unittest import mock

import dns.resolver

import pytest
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers
from dns.rdatatype import UnknownRdatatype

from dnsutils.dkim import _find_dkim_record, get_dkim, main, parse_dkim_record
from dnsutils.exceptions import (
    DKIMRecordNotFoundError,
    DNSLookupError,
    DomainNotFoundError,
    InvalidRecordTypeError,
    NoNameserversError,
    NoRecordsError,
    TimeoutError as DNSTimeoutError,
)


class MockAnswer:
    """Mock DNS answer object."""

    def __init__(self, records: list[str] | None = None) -> None:
        if records is None:
            records = ["v=DKIM1; k=rsa; p=MIGfMA0GCSq..."]
        self.records = records

    def __iter__(self) -> Iterator[MockRdata]:
        """Return iterator over mock rdata objects."""
        return iter([MockRdata(record) for record in self.records])


class MockRdata:
    """Mock rdata object."""

    def __init__(self, record: str) -> None:
        self.strings: list[bytes] = [record.encode()]


# Tests for parse_dkim_record()


def test_parse_dkim_record_basic() -> None:
    """Test parsing basic DKIM record."""
    record = "v=DKIM1; k=rsa; p=MIGfMA0GCSq..."
    parsed = parse_dkim_record(record)

    assert parsed["v"] == "DKIM1"
    assert parsed["k"] == "rsa"
    assert parsed["p"] == "MIGfMA0GCSq..."


def test_parse_dkim_record_with_hash() -> None:
    """Test parsing DKIM record with hash algorithm."""
    record = "v=DKIM1; h=sha256; k=rsa; p=MIGfMA0GCSq..."
    parsed = parse_dkim_record(record)

    assert parsed["v"] == "DKIM1"
    assert parsed["h"] == "sha256"
    assert parsed["k"] == "rsa"


def test_parse_dkim_record_complex() -> None:
    """Test parsing complex DKIM record."""
    record = "v=DKIM1; k=rsa; p=MIGfMA0GCSq...; t=s; h=sha256; s=email"
    parsed = parse_dkim_record(record)

    assert parsed["v"] == "DKIM1"
    assert parsed["k"] == "rsa"
    assert parsed["t"] == "s"
    assert parsed["h"] == "sha256"
    assert parsed["s"] == "email"


# Tests for get_dkim()


def test_get_dkim_success(capsys) -> None:
    """Test successful DKIM lookup."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )
    mock_answer = MockAnswer()

    with mock.patch("dnsutils.dkim.resolve_dns_records", return_value=mock_answer):
        get_dkim(args)
        captured = capsys.readouterr()
        assert "v=DKIM1" in captured.out


def test_get_dkim_multiple_txt_records(capsys) -> None:
    """Test DKIM lookup when multiple TXT records exist."""
    args = argparse.Namespace(domain="example.com", selector="google", nameservers=None)
    records = [
        "some other txt record",
        "v=DKIM1; k=rsa; p=MIGfMA0GCSq...",
        "another txt record",
    ]
    mock_answer = MockAnswer(records)

    with mock.patch("dnsutils.dkim.resolve_dns_records", return_value=mock_answer):
        get_dkim(args)
        captured = capsys.readouterr()
        assert "v=DKIM1" in captured.out


def test_get_dkim_custom_nameservers() -> None:
    """Test DKIM lookup with custom nameservers."""
    args = argparse.Namespace(
        domain="example.com",
        selector="default",
        nameservers=["8.8.8.8", "1.1.1.1"],
    )
    mock_answer = MockAnswer()

    with mock.patch(
        "dnsutils.dkim.resolve_dns_records", return_value=mock_answer
    ) as mock_resolve:
        with mock.patch("dnsutils.dkim.logger"):
            get_dkim(args)

        # Verify nameservers were passed to resolve function
        mock_resolve.assert_called_once()
        call_args = mock_resolve.call_args
        assert call_args[0][2] == ["8.8.8.8", "1.1.1.1"]


def test_get_dkim_nxdomain() -> None:
    """Test that NXDOMAIN raises DomainNotFoundError."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NXDOMAIN()):
        with pytest.raises(DomainNotFoundError):
            get_dkim(args)


def test_get_dkim_no_answer() -> None:
    """Test that NoAnswer raises NoRecordsError."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NoAnswer()):
        with pytest.raises(NoRecordsError):
            get_dkim(args)


def test_get_dkim_no_nameservers() -> None:
    """Test that NoNameservers raises NoNameserversError."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NoNameservers()):
        with pytest.raises(NoNameserversError):
            get_dkim(args)


def test_get_dkim_timeout() -> None:
    """Test that Timeout raises DNSTimeoutError."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=Timeout()):
        with pytest.raises(DNSTimeoutError):
            get_dkim(args)


def test_get_dkim_invalid_record_type() -> None:
    """Test that UnknownRdatatype raises InvalidRecordTypeError."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=UnknownRdatatype()):
        with pytest.raises(InvalidRecordTypeError):
            get_dkim(args)


def test_get_dkim_record_not_found() -> None:
    """Test that missing DKIM record raises DKIMRecordNotFoundError."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )
    mock_answer = MockAnswer(records=["other txt record"])

    with mock.patch("dnsutils.dkim.resolve_dns_records", return_value=mock_answer):
        with pytest.raises(DKIMRecordNotFoundError):
            get_dkim(args)


def test_find_dkim_record_success() -> None:
    """Test finding DKIM record among multiple records."""
    records = [
        "some other txt",
        "v=DKIM1; k=rsa; p=MIGfMA0GCSq...",
        "another txt",
    ]
    mock_answer = MockAnswer(records)
    result = _find_dkim_record(cast(dns.resolver.Answer, mock_answer))
    assert result == "v=DKIM1; k=rsa; p=MIGfMA0GCSq..."


def test_find_dkim_record_not_found() -> None:
    """Test that missing DKIM record raises error."""
    mock_answer = MockAnswer(records=["other txt record"])
    with pytest.raises(DKIMRecordNotFoundError):
        _find_dkim_record(cast(dns.resolver.Answer, mock_answer))


# Tests for main()


def test_main_success(capsys) -> None:
    """Test main() succeeds with valid arguments."""
    mock_answer = MockAnswer()

    with mock.patch.object(sys, "argv", ["dkim", "example.com", "default"]):
        with mock.patch("dnsutils.dkim.resolve_dns_records", return_value=mock_answer):
            main()
            captured = capsys.readouterr()
            assert "v=DKIM1" in captured.out


def test_main_error_logs_to_stderr(caplog) -> None:
    """Test main() logs error to stderr on DKIM lookup failure."""
    with mock.patch.object(sys, "argv", ["dkim", "nonexistent.invalid", "default"]):
        with mock.patch(
            "dnsutils.dkim.resolve_dns_records",
            side_effect=DomainNotFoundError(
                "Domain not found", domain="nonexistent.invalid"
            ),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "nonexistent.invalid" in caplog.text


def test_main_with_custom_nameservers() -> None:
    """Test main() with --nameservers argument."""
    mock_answer = MockAnswer()

    with mock.patch.object(
        sys,
        "argv",
        ["dkim", "example.com", "default", "--nameservers", "8.8.8.8", "1.1.1.1"],
    ):
        with mock.patch(
            "dnsutils.dkim.resolve_dns_records", return_value=mock_answer
        ) as mock_resolve:
            with mock.patch("dnsutils.dkim.logger"):
                main()

            # Verify nameservers were passed
            mock_resolve.assert_called_once()
            call_args = mock_resolve.call_args
            assert call_args[0][2] == ["8.8.8.8", "1.1.1.1"]


def test_main_preserves_original_exception() -> None:
    """Test that DKIMRecordNotFoundError preserves original exception."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )
    original_error = NXDOMAIN("The DNS query name does not exist")

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=original_error):
        with pytest.raises(DomainNotFoundError):
            get_dkim(args)


def test_main_no_records_error(caplog) -> None:
    """Test main() logs error on NoRecordsError."""
    with mock.patch.object(sys, "argv", ["dkim", "example.com", "default"]):
        with mock.patch(
            "dnsutils.dkim.resolve_dns_records",
            side_effect=NoRecordsError("No records", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "example.com" in caplog.text


def test_main_dkim_record_not_found(caplog) -> None:
    """Test main() logs error on DKIMRecordNotFoundError."""
    with mock.patch.object(sys, "argv", ["dkim", "example.com", "default"]):
        with mock.patch(
            "dnsutils.dkim.resolve_dns_records",
            side_effect=DKIMRecordNotFoundError("No DKIM record", record_type="DKIM"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "v=DKIM1" in caplog.text


def test_main_timeout_error(caplog) -> None:
    """Test main() logs error on DNSTimeoutError."""
    with mock.patch.object(sys, "argv", ["dkim", "example.com", "default"]):
        with mock.patch(
            "dnsutils.dkim.resolve_dns_records",
            side_effect=DNSTimeoutError("Timeout", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "timed out" in caplog.text


def test_main_dns_lookup_error(caplog) -> None:
    """Test main() logs error on DNSLookupError."""
    with mock.patch.object(sys, "argv", ["dkim", "example.com", "default"]):
        with mock.patch(
            "dnsutils.dkim.resolve_dns_records",
            side_effect=DNSLookupError("DNS lookup failed", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "DNS lookup failed" in caplog.text


def test_get_dkim_with_hash_algorithm(capsys) -> None:
    """Test DKIM lookup with hash algorithm."""
    args = argparse.Namespace(
        domain="example.com", selector="default", nameservers=None
    )
    record = "v=DKIM1; h=sha256; k=rsa; p=MIGfMA0GCSq..."
    mock_answer = MockAnswer([record])

    with mock.patch("dnsutils.dkim.resolve_dns_records", return_value=mock_answer):
        get_dkim(args)
        captured = capsys.readouterr()
        assert "Hash Algorithm:" in captured.out
        assert "sha256" in captured.out
