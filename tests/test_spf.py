"""Tests for the spf module."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Iterator
from unittest import mock

import pytest
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers
from dns.rdatatype import UnknownRdatatype

from dnsutils.exceptions import (
    DNSLookupError,
    DomainNotFoundError,
    InvalidRecordTypeError,
    NoNameserversError,
    NoRecordsError,
    SPFRecordNotFoundError,
    TimeoutError as DNSTimeoutError,
)
from dnsutils.spf import _find_spf_record, get_spf, main, parse_spf_record


class MockAnswer:
    """Mock DNS answer object."""

    def __init__(self, records: list[str] | None = None) -> None:
        if records is None:
            records = ["v=spf1 include:_spf.google.com ~all"]
        self.records = records

    def __iter__(self) -> Iterator[MockRdata]:
        """Return iterator over mock rdata objects."""
        return iter([MockRdata(record) for record in self.records])


class MockRdata:
    """Mock rdata object."""

    def __init__(self, record: str) -> None:
        self.strings: list[bytes] = [record.encode()]


# Tests for parse_spf_record()


def test_parse_spf_record_basic() -> None:
    """Test parsing basic SPF record."""
    record = "v=spf1 include:_spf.google.com ~all"
    parsed = parse_spf_record(record)

    assert parsed["version"] == "spf1"
    assert "include:_spf.google.com" in parsed["mechanisms"]
    assert "~all" in parsed["mechanisms"]


def test_parse_spf_record_with_modifiers() -> None:
    """Test parsing SPF record with modifiers."""
    record = "v=spf1 ip4:192.0.2.1 -all exp=explain.example.com"
    parsed = parse_spf_record(record)

    assert parsed["version"] == "spf1"
    assert "ip4:192.0.2.1" in parsed["mechanisms"]
    modifiers = parsed.get("modifiers", {})
    assert isinstance(modifiers, dict)
    assert modifiers.get("exp") == "explain.example.com"


def test_parse_spf_record_complex() -> None:
    """Test parsing complex SPF record."""
    record = "v=spf1 a mx ip4:192.0.2.0/24 -all"
    parsed = parse_spf_record(record)

    assert parsed["version"] == "spf1"
    assert "a" in parsed["mechanisms"]
    assert "mx" in parsed["mechanisms"]
    assert "ip4:192.0.2.0/24" in parsed["mechanisms"]


# Tests for get_spf()


def test_get_spf_success(capsys) -> None:
    """Test successful SPF lookup."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    mock_answer = MockAnswer()

    with mock.patch("dnsutils.spf.resolve_dns_records", return_value=mock_answer):
        get_spf(args)
        captured = capsys.readouterr()
        assert "v=spf1" in captured.out


def test_get_spf_multiple_txt_records(capsys) -> None:
    """Test SPF lookup when multiple TXT records exist."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    records = [
        "some other txt record",
        "v=spf1 include:_spf.google.com ~all",
        "another txt record",
    ]
    mock_answer = MockAnswer(records)

    with mock.patch("dnsutils.spf.resolve_dns_records", return_value=mock_answer):
        get_spf(args)
        captured = capsys.readouterr()
        assert "v=spf1" in captured.out


def test_get_spf_custom_nameservers() -> None:
    """Test SPF lookup with custom nameservers."""
    args = argparse.Namespace(
        domain="example.com",
        nameservers=["8.8.8.8", "1.1.1.1"],
    )
    mock_answer = MockAnswer()

    with mock.patch(
        "dnsutils.spf.resolve_dns_records", return_value=mock_answer
    ) as mock_resolve:
        with mock.patch("dnsutils.spf.logger"):
            get_spf(args)

        # Verify nameservers were passed to resolve function
        mock_resolve.assert_called_once()
        call_args = mock_resolve.call_args
        assert call_args[0][2] == ["8.8.8.8", "1.1.1.1"]


def test_get_spf_nxdomain() -> None:
    """Test that NXDOMAIN raises DomainNotFoundError."""
    args = argparse.Namespace(domain="nonexistent.invalid", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NXDOMAIN()):
        with pytest.raises(DomainNotFoundError):
            get_spf(args)


def test_get_spf_no_answer() -> None:
    """Test that NoAnswer raises NoRecordsError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NoAnswer()):
        with pytest.raises(NoRecordsError):
            get_spf(args)


def test_get_spf_no_nameservers() -> None:
    """Test that NoNameservers raises NoNameserversError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NoNameservers()):
        with pytest.raises(NoNameserversError):
            get_spf(args)


def test_get_spf_timeout() -> None:
    """Test that Timeout raises DNSTimeoutError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=Timeout()):
        with pytest.raises(DNSTimeoutError):
            get_spf(args)


def test_get_spf_invalid_record_type() -> None:
    """Test that UnknownRdatatype raises InvalidRecordTypeError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=UnknownRdatatype()):
        with pytest.raises(InvalidRecordTypeError):
            get_spf(args)


def test_get_spf_record_not_found() -> None:
    """Test that missing SPF record raises SPFRecordNotFoundError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    mock_answer = MockAnswer(records=["other txt record"])

    with mock.patch("dnsutils.spf.resolve_dns_records", return_value=mock_answer):
        with pytest.raises(SPFRecordNotFoundError):
            get_spf(args)


def test_find_spf_record_success() -> None:
    """Test finding SPF record among multiple records."""
    records = [
        "some other txt",
        "v=spf1 include:_spf.example.com ~all",
        "another txt",
    ]
    mock_answer = MockAnswer(records)
    result = _find_spf_record(mock_answer)  # type: ignore[arg-type]
    assert result == "v=spf1 include:_spf.example.com ~all"


def test_find_spf_record_not_found() -> None:
    """Test that missing SPF record raises error."""
    mock_answer = MockAnswer(records=["other txt record"])
    with pytest.raises(SPFRecordNotFoundError):
        _find_spf_record(mock_answer)  # type: ignore[arg-type]


# Tests for main()


def test_main_success(capsys) -> None:
    """Test main() succeeds with valid arguments."""
    mock_answer = MockAnswer()

    with mock.patch.object(sys, "argv", ["spf", "example.com"]):
        with mock.patch("dnsutils.spf.resolve_dns_records", return_value=mock_answer):
            main()
            captured = capsys.readouterr()
            assert "v=spf1" in captured.out


def test_main_error_logs_to_stderr(caplog) -> None:
    """Test main() logs error to stderr on SPF lookup failure."""
    with mock.patch.object(sys, "argv", ["spf", "nonexistent.invalid"]):
        with mock.patch(
            "dnsutils.spf.resolve_dns_records",
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
        ["spf", "example.com", "--nameservers", "8.8.8.8", "1.1.1.1"],
    ):
        with mock.patch(
            "dnsutils.spf.resolve_dns_records", return_value=mock_answer
        ) as mock_resolve:
            with mock.patch("dnsutils.spf.logger"):
                main()

            # Verify nameservers were passed
            mock_resolve.assert_called_once()
            call_args = mock_resolve.call_args
            assert call_args[0][2] == ["8.8.8.8", "1.1.1.1"]


def test_main_no_records_error(caplog) -> None:
    """Test main() logs error on NoRecordsError."""
    with mock.patch.object(sys, "argv", ["spf", "example.com"]):
        with mock.patch(
            "dnsutils.spf.resolve_dns_records",
            side_effect=NoRecordsError("No records", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "example.com" in caplog.text


def test_main_spf_record_not_found(caplog) -> None:
    """Test main() logs error on SPFRecordNotFoundError."""
    with mock.patch.object(sys, "argv", ["spf", "example.com"]):
        with mock.patch(
            "dnsutils.spf.resolve_dns_records",
            side_effect=SPFRecordNotFoundError("No SPF record", record_type="SPF"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "v=spf1" in caplog.text


def test_main_timeout_error(caplog) -> None:
    """Test main() logs error on DNSTimeoutError."""
    with mock.patch.object(sys, "argv", ["spf", "example.com"]):
        with mock.patch(
            "dnsutils.spf.resolve_dns_records",
            side_effect=DNSTimeoutError("Timeout", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "timed out" in caplog.text


def test_main_dns_lookup_error(caplog) -> None:
    """Test main() logs error on DNSLookupError."""
    with mock.patch.object(sys, "argv", ["spf", "example.com"]):
        with mock.patch(
            "dnsutils.spf.resolve_dns_records",
            side_effect=DNSLookupError("DNS lookup failed", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "DNS lookup failed" in caplog.text


def test_get_spf_with_modifiers(capsys) -> None:
    """Test SPF lookup with modifiers."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    record = "v=spf1 a mx ip4:192.0.2.0/24 -all exp=explain.example.com"
    mock_answer = MockAnswer([record])

    with mock.patch("dnsutils.spf.resolve_dns_records", return_value=mock_answer):
        get_spf(args)
        captured = capsys.readouterr()
        assert "Modifiers:" in captured.out
        assert "exp=explain.example.com" in captured.out
