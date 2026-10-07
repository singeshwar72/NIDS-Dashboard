"""
Tests for detection/validators.py
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.validators import (
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_ip,
    is_valid_port,
    is_valid_protocol,
    normalize_protocol,
    is_valid_timestamp,
    validate_csv_columns,
    validate_row,
    validate_file_extension,
    safe_float,
    safe_int,
)


class TestIPv4Validation:
    def test_valid_ipv4(self):
        assert is_valid_ipv4("192.168.1.1") is True

    def test_valid_ipv4_loopback(self):
        assert is_valid_ipv4("127.0.0.1") is True

    def test_valid_ipv4_broadcast(self):
        assert is_valid_ipv4("255.255.255.255") is True

    def test_invalid_ipv4_out_of_range(self):
        assert is_valid_ipv4("300.1.1.1") is False

    def test_invalid_ipv4_string(self):
        assert is_valid_ipv4("not-an-ip") is False

    def test_empty_string(self):
        assert is_valid_ipv4("") is False


class TestIPv6Validation:
    def test_valid_ipv6_full(self):
        assert is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_valid_ipv6_compressed(self):
        assert is_valid_ipv6("::1") is True

    def test_invalid_ipv6(self):
        assert is_valid_ipv6("gggg::1") is False

    def test_invalid_ipv6_ipv4_like(self):
        assert is_valid_ipv6("192.168.1.1") is False


class TestPortValidation:
    def test_valid_port_zero(self):
        assert is_valid_port(0) is True

    def test_valid_port_max(self):
        assert is_valid_port(65535) is True

    def test_invalid_port_negative(self):
        assert is_valid_port(-1) is False

    def test_invalid_port_too_large(self):
        assert is_valid_port(70000) is False

    def test_valid_port_string(self):
        assert is_valid_port("8080") is True


class TestProtocolValidation:
    def test_valid_tcp(self):
        assert is_valid_protocol("TCP") is True

    def test_valid_lowercase(self):
        # is_valid_protocol normalizes case internally before checking
        assert is_valid_protocol("tcp") is True

    def test_normalize_protocol_uppercase(self):
        assert normalize_protocol("tcp") == "TCP"

    def test_normalize_unknown(self):
        assert normalize_protocol("XYZ123") == "OTHER"

    def test_normalize_empty(self):
        assert normalize_protocol("") == "OTHER"


class TestTimestampValidation:
    def test_valid_timestamp(self):
        assert is_valid_timestamp("2024-01-15 08:00:01") is True

    def test_valid_iso_timestamp(self):
        assert is_valid_timestamp("2024-01-15T08:00:01") is True

    def test_invalid_timestamp(self):
        assert is_valid_timestamp("not-a-date") is False

    def test_none_timestamp(self):
        assert is_valid_timestamp(None) is False


class TestCSVColumnValidation:
    def test_valid_columns(self):
        ok, msg = validate_csv_columns(["source_ip", "destination_ip", "timestamp"])
        assert ok is True

    def test_missing_required_column(self):
        ok, msg = validate_csv_columns(["source_ip", "timestamp"])
        assert ok is False
        assert "destination_ip" in msg

    def test_missing_both(self):
        ok, msg = validate_csv_columns(["timestamp", "protocol"])
        assert ok is False


class TestRowValidation:
    def test_valid_row(self):
        row = {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "source_port": "54321",
            "destination_port": "53",
            "protocol": "DNS",
            "packet_count": "5",
            "packet_size": "60",
            "duration": "0.5",
            "bytes_sent": "300",
            "bytes_received": "280",
            "connection_count": "2",
            "timestamp": "2024-01-15 08:00:01",
        }
        is_valid, reason, sanitized = validate_row(row)
        assert is_valid is True
        assert sanitized["source_ip"] == "192.168.1.10"
        assert sanitized["protocol"] == "DNS"

    def test_invalid_source_ip(self):
        row = {"source_ip": "999.999.999.999", "destination_ip": "8.8.8.8"}
        is_valid, reason, _ = validate_row(row)
        assert is_valid is False
        assert "source_ip" in reason

    def test_invalid_port(self):
        row = {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "source_port": "99999",
        }
        is_valid, reason, _ = validate_row(row)
        assert is_valid is False

    def test_negative_packet_count(self):
        row = {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "packet_count": "-10",
        }
        is_valid, reason, _ = validate_row(row)
        assert is_valid is False

    def test_file_extension_valid(self):
        assert validate_file_extension("traffic.csv") is True

    def test_file_extension_invalid(self):
        assert validate_file_extension("traffic.exe") is False

    def test_safe_float(self):
        assert safe_float("3.14") == pytest.approx(3.14)
        assert safe_float("invalid") == 0.0
        assert safe_float(None) == 0.0

    def test_safe_int(self):
        assert safe_int("42") == 42
        assert safe_int("bad") == 0
