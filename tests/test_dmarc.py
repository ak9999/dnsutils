"""Tests for the dmarc module."""

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

from dnsutils.dmarc import (
    _find_dmarc_record,
    analyze_dmarc_policy,
    get_dmarc,
    main,
    parse_dmarc_record,
)
from dnsutils.exceptions import (
    DMARCRecordNotFoundError,
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
            records = ["v=DMARC1; p=none; rua=mailto:admin@example.com"]
        self.records = records

    def __iter__(self) -> Iterator[MockRdata]:
        """Return iterator over mock rdata objects."""
        return iter([MockRdata(record) for record in self.records])


class MockRdata:
    """Mock rdata object."""

    def __init__(self, record: str) -> None:
        self.strings: list[bytes] = [record.encode()]


# Tests for parse_dmarc_record()


def test_parse_dmarc_record_basic() -> None:
    """Test parsing basic DMARC record."""
    record = "v=DMARC1; p=none"
    parsed = parse_dmarc_record(record)

    assert parsed["v"] == "DMARC1"
    assert parsed["p"] == "none"


def test_parse_dmarc_record_full() -> None:
    """Test parsing full DMARC record."""
    record = "v=DMARC1; p=quarantine; rua=mailto:admin@example.com; ruf=mailto:forensics@example.com"
    parsed = parse_dmarc_record(record)

    assert parsed["v"] == "DMARC1"
    assert parsed["p"] == "quarantine"
    assert parsed["rua"] == "mailto:admin@example.com"
    assert parsed["ruf"] == "mailto:forensics@example.com"


def test_parse_dmarc_record_with_alignment() -> None:
    """Test parsing DMARC record with alignment settings."""
    record = "v=DMARC1; p=reject; adkim=s; aspf=s; pct=100"
    parsed = parse_dmarc_record(record)

    assert parsed["v"] == "DMARC1"
    assert parsed["p"] == "reject"
    assert parsed["adkim"] == "s"
    assert parsed["aspf"] == "s"
    assert parsed["pct"] == "100"


# Tests for analyze_dmarc_policy()


def test_analyze_dmarc_policy_reject() -> None:
    """Test analysis of reject policy."""
    parsed = {"v": "DMARC1", "p": "reject", "pct": "100"}
    analysis = analyze_dmarc_policy(parsed)

    assert analysis["version"] == "DMARC1"
    assert analysis["policy"] == "reject"
    assert "Strong" in analysis["policy_strength"]


def test_analyze_dmarc_policy_quarantine() -> None:
    """Test analysis of quarantine policy."""
    parsed = {"v": "DMARC1", "p": "quarantine", "pct": "50"}
    analysis = analyze_dmarc_policy(parsed)

    assert analysis["policy"] == "quarantine"
    assert "Medium" in analysis["policy_strength"]
    assert analysis["percentage"] == "50"


def test_analyze_dmarc_policy_none() -> None:
    """Test analysis of none policy."""
    parsed = {"v": "DMARC1", "p": "none"}
    analysis = analyze_dmarc_policy(parsed)

    assert analysis["policy"] == "none"
    assert "Weak" in analysis["policy_strength"]


def test_analyze_dmarc_policy_defaults() -> None:
    """Test analysis with default values."""
    parsed = {"v": "DMARC1"}
    analysis = analyze_dmarc_policy(parsed)

    assert analysis["version"] == "DMARC1"
    assert analysis["policy"] == "none"
    assert analysis["alignment_dkim"] == "r"
    assert analysis["alignment_spf"] == "r"
    assert analysis["percentage"] == "100"


# Tests for get_dmarc()


def test_get_dmarc_success(capsys) -> None:
    """Test successful DMARC lookup."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    mock_answer = MockAnswer()

    with mock.patch("dnsutils.dmarc.resolve_dns_records", return_value=mock_answer):
        get_dmarc(args)
        captured = capsys.readouterr()
        assert "v=DMARC1" in captured.out


def test_get_dmarc_multiple_txt_records(capsys) -> None:
    """Test DMARC lookup when multiple TXT records exist."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    records = [
        "some other txt record",
        "v=DMARC1; p=reject; rua=mailto:admin@example.com",
        "another txt record",
    ]
    mock_answer = MockAnswer(records)

    with mock.patch("dnsutils.dmarc.resolve_dns_records", return_value=mock_answer):
        get_dmarc(args)
        captured = capsys.readouterr()
        assert "v=DMARC1" in captured.out


def test_get_dmarc_custom_nameservers() -> None:
    """Test DMARC lookup with custom nameservers."""
    args = argparse.Namespace(
        domain="example.com",
        nameservers=["8.8.8.8", "1.1.1.1"],
    )
    mock_answer = MockAnswer()

    with mock.patch(
        "dnsutils.dmarc.resolve_dns_records", return_value=mock_answer
    ) as mock_resolve:
        with mock.patch("dnsutils.dmarc.logger"):
            get_dmarc(args)

        # Verify nameservers were passed to resolve function
        mock_resolve.assert_called_once()
        call_args = mock_resolve.call_args
        assert call_args[0][2] == ["8.8.8.8", "1.1.1.1"]


def test_get_dmarc_nxdomain() -> None:
    """Test that NXDOMAIN raises DomainNotFoundError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NXDOMAIN()):
        with pytest.raises(DomainNotFoundError):
            get_dmarc(args)


def test_get_dmarc_no_answer() -> None:
    """Test that NoAnswer raises NoRecordsError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NoAnswer()):
        with pytest.raises(NoRecordsError):
            get_dmarc(args)


def test_get_dmarc_no_nameservers() -> None:
    """Test that NoNameservers raises NoNameserversError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=NoNameservers()):
        with pytest.raises(NoNameserversError):
            get_dmarc(args)


def test_get_dmarc_timeout() -> None:
    """Test that Timeout raises DNSTimeoutError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=Timeout()):
        with pytest.raises(DNSTimeoutError):
            get_dmarc(args)


def test_get_dmarc_invalid_record_type() -> None:
    """Test that UnknownRdatatype raises InvalidRecordTypeError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=UnknownRdatatype()):
        with pytest.raises(InvalidRecordTypeError):
            get_dmarc(args)


def test_get_dmarc_record_not_found() -> None:
    """Test that missing DMARC record raises DMARCRecordNotFoundError."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    mock_answer = MockAnswer(records=["other txt record"])

    with mock.patch("dnsutils.dmarc.resolve_dns_records", return_value=mock_answer):
        with pytest.raises(DMARCRecordNotFoundError):
            get_dmarc(args)


def test_find_dmarc_record_success() -> None:
    """Test finding DMARC record among multiple records."""
    records = [
        "some other txt",
        "v=DMARC1; p=reject; rua=mailto:admin@example.com",
        "another txt",
    ]
    mock_answer = MockAnswer(records)
    result = _find_dmarc_record(mock_answer)  # type: ignore[arg-type]
    assert result == "v=DMARC1; p=reject; rua=mailto:admin@example.com"


def test_find_dmarc_record_not_found() -> None:
    """Test that missing DMARC record raises error."""
    mock_answer = MockAnswer(records=["other txt record"])
    with pytest.raises(DMARCRecordNotFoundError):
        _find_dmarc_record(mock_answer)  # type: ignore[arg-type]


# Tests for main()


def test_main_success(capsys) -> None:
    """Test main() succeeds with valid arguments."""
    mock_answer = MockAnswer()

    with mock.patch.object(sys, "argv", ["dmarc", "example.com"]):
        with mock.patch("dnsutils.dmarc.resolve_dns_records", return_value=mock_answer):
            main()
            captured = capsys.readouterr()
            assert "v=DMARC1" in captured.out


def test_main_error_logs_to_stderr(caplog) -> None:
    """Test main() logs error to stderr on DMARC lookup failure."""
    with mock.patch.object(sys, "argv", ["dmarc", "nonexistent.invalid"]):
        with mock.patch(
            "dnsutils.dmarc.resolve_dns_records",
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
        ["dmarc", "example.com", "--nameservers", "8.8.8.8", "1.1.1.1"],
    ):
        with mock.patch(
            "dnsutils.dmarc.resolve_dns_records", return_value=mock_answer
        ) as mock_resolve:
            with mock.patch("dnsutils.dmarc.logger"):
                main()

            # Verify nameservers were passed
            mock_resolve.assert_called_once()
            call_args = mock_resolve.call_args
            assert call_args[0][2] == ["8.8.8.8", "1.1.1.1"]


def test_main_preserves_original_exception() -> None:
    """Test that DMARCRecordNotFoundError preserves original exception."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    original_error = NXDOMAIN("The DNS query name does not exist")

    with mock.patch("dns.resolver.Resolver.resolve", side_effect=original_error):
        with pytest.raises(DomainNotFoundError):
            get_dmarc(args)


def test_main_no_records_error(caplog) -> None:
    """Test main() logs error on NoRecordsError."""
    with mock.patch.object(sys, "argv", ["dmarc", "example.com"]):
        with mock.patch(
            "dnsutils.dmarc.resolve_dns_records",
            side_effect=NoRecordsError("No records", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "example.com" in caplog.text


def test_main_dmarc_record_not_found(caplog) -> None:
    """Test main() logs error on DMARCRecordNotFoundError."""
    with mock.patch.object(sys, "argv", ["dmarc", "example.com"]):
        with mock.patch(
            "dnsutils.dmarc.resolve_dns_records",
            side_effect=DMARCRecordNotFoundError("No DMARC record", record_type="DMARC"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "v=DMARC1" in caplog.text


def test_main_timeout_error(caplog) -> None:
    """Test main() logs error on DNSTimeoutError."""
    with mock.patch.object(sys, "argv", ["dmarc", "example.com"]):
        with mock.patch(
            "dnsutils.dmarc.resolve_dns_records",
            side_effect=DNSTimeoutError("Timeout", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "timed out" in caplog.text


def test_main_dns_lookup_error(caplog) -> None:
    """Test main() logs error on DNSLookupError."""
    with mock.patch.object(sys, "argv", ["dmarc", "example.com"]):
        with mock.patch(
            "dnsutils.dmarc.resolve_dns_records",
            side_effect=DNSLookupError("DNS lookup failed", domain="example.com", record_type="TXT"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                with caplog.at_level(logging.ERROR):
                    main()
            assert exc_info.value.code == 1
            assert "DNS lookup failed" in caplog.text


def test_get_dmarc_with_reports(capsys) -> None:
    """Test DMARC lookup with aggregate and forensic reports."""
    args = argparse.Namespace(domain="example.com", nameservers=None)
    record = "v=DMARC1; p=reject; rua=mailto:admin@example.com; ruf=mailto:forensics@example.com"
    mock_answer = MockAnswer([record])

    with mock.patch("dnsutils.dmarc.resolve_dns_records", return_value=mock_answer):
        get_dmarc(args)
        captured = capsys.readouterr()
        assert "Aggregate Report URI:" in captured.out
        assert "Forensic Report URI:" in captured.out
