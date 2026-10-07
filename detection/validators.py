"""
NIDS Dashboard - Input Validators
Validates all incoming traffic data fields before processing.
Rejects invalid records safely; never trusts uploaded data.
"""

import ipaddress
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Constants
# ------------------------------------------------------------------ #

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "FTP", "SSH", "SMTP", "OTHER"}
PORT_MIN = 0
PORT_MAX = 65535
MAX_PACKET_COUNT = 10_000_000
MAX_PACKET_SIZE = 65535
MAX_BYTES = 10_000_000_000
MAX_DURATION = 86400  # 24 hours
MAX_CONNECTION_COUNT = 100_000

REQUIRED_COLUMNS = {
    "source_ip",
    "destination_ip",
}

OPTIONAL_NUMERIC_COLUMNS = [
    "source_port",
    "destination_port",
    "packet_count",
    "packet_size",
    "duration",
    "bytes_sent",
    "bytes_received",
    "connection_count",
]

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]


# ------------------------------------------------------------------ #
# IP Validators
# ------------------------------------------------------------------ #

def is_valid_ipv4(ip: str) -> bool:
    """Return True if ip is a valid IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        return True
    except (ipaddress.AddressValueError, AttributeError):
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Return True if ip is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip.strip())
        return True
    except (ipaddress.AddressValueError, AttributeError):
        return False


def is_valid_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 or IPv6 address."""
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


# ------------------------------------------------------------------ #
# Port / Protocol Validators
# ------------------------------------------------------------------ #

def is_valid_port(port: Any) -> bool:
    """Return True if port is an integer in [0, 65535]."""
    try:
        p = int(float(str(port)))
        return PORT_MIN <= p <= PORT_MAX
    except (ValueError, TypeError):
        return False


def is_valid_protocol(protocol: Any) -> bool:
    """Return True if protocol is one of the known values."""
    if protocol is None:
        return True  # optional field
    return str(protocol).strip().upper() in VALID_PROTOCOLS


def normalize_protocol(protocol: Any) -> str:
    """Normalize protocol string to uppercase or return OTHER."""
    if not protocol or str(protocol).strip() == "":
        return "OTHER"
    p = str(protocol).strip().upper()
    return p if p in VALID_PROTOCOLS else "OTHER"


# ------------------------------------------------------------------ #
# Numeric Validators
# ------------------------------------------------------------------ #

def is_valid_positive_number(value: Any, max_val: float = 1e12) -> bool:
    """Return True if value is a non-negative number within max_val."""
    try:
        v = float(str(value))
        return 0 <= v <= max_val
    except (ValueError, TypeError):
        return False


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert value to float safely."""
    try:
        v = float(str(value))
        return v if v == v else default  # NaN check
    except (ValueError, TypeError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """Convert value to int safely."""
    try:
        return int(float(str(value)))
    except (ValueError, TypeError):
        return default


# ------------------------------------------------------------------ #
# Timestamp Validator
# ------------------------------------------------------------------ #

def is_valid_timestamp(ts: Any) -> bool:
    """Return True if ts can be parsed as a datetime string."""
    if not ts or not isinstance(ts, str):
        return False
    for fmt in TIMESTAMP_FORMATS:
        try:
            datetime.strptime(ts.strip(), fmt)
            return True
        except ValueError:
            continue
    return False


def normalize_timestamp(ts: Any) -> str:
    """Parse and normalize timestamp to ISO format. Returns current time if invalid."""
    if ts and isinstance(ts, str):
        for fmt in TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(ts.strip(), fmt)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------ #
# CSV Structure Validators
# ------------------------------------------------------------------ #

def validate_csv_columns(columns: List[str]) -> Tuple[bool, str]:
    """Check that all required columns are present."""
    cols_lower = {c.strip().lower() for c in columns}
    missing = REQUIRED_COLUMNS - cols_lower
    if missing:
        return False, f"Missing required columns: {', '.join(sorted(missing))}"
    return True, "OK"


# ------------------------------------------------------------------ #
# Row Validator
# ------------------------------------------------------------------ #

def validate_row(row: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validate and sanitize a single traffic row.

    Returns:
        (is_valid, reason, sanitized_record)
    """
    errors = []

    # Source IP
    src_ip = str(row.get("source_ip", "")).strip()
    if not is_valid_ip(src_ip):
        errors.append(f"Invalid source_ip: {src_ip!r}")

    # Destination IP
    dst_ip = str(row.get("destination_ip", "")).strip()
    if not is_valid_ip(dst_ip):
        errors.append(f"Invalid destination_ip: {dst_ip!r}")

    if errors:
        return False, "; ".join(errors), {}

    # Ports (optional but validated if present)
    src_port_raw = row.get("source_port")
    dst_port_raw = row.get("destination_port")

    if src_port_raw not in (None, "", "nan") and not is_valid_port(src_port_raw):
        errors.append(f"Invalid source_port: {src_port_raw!r}")
    if dst_port_raw not in (None, "", "nan") and not is_valid_port(dst_port_raw):
        errors.append(f"Invalid destination_port: {dst_port_raw!r}")

    # Numeric fields (optional, must be non-negative if present)
    numeric_checks = {
        "packet_count": MAX_PACKET_COUNT,
        "packet_size": MAX_PACKET_SIZE,
        "duration": MAX_DURATION,
        "bytes_sent": MAX_BYTES,
        "bytes_received": MAX_BYTES,
        "connection_count": MAX_CONNECTION_COUNT,
    }
    for field, max_val in numeric_checks.items():
        val = row.get(field)
        if val not in (None, "", "nan") and not is_valid_positive_number(val, max_val):
            errors.append(f"Invalid {field}: {val!r}")

    if errors:
        return False, "; ".join(errors), {}

    # Build sanitized record
    sanitized: Dict[str, Any] = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": safe_int(src_port_raw, 0),
        "destination_port": safe_int(dst_port_raw, 0),
        "protocol": normalize_protocol(row.get("protocol")),
        "packet_count": safe_float(row.get("packet_count"), 0.0),
        "packet_size": safe_float(row.get("packet_size"), 0.0),
        "duration": safe_float(row.get("duration"), 0.0),
        "bytes_sent": safe_float(row.get("bytes_sent"), 0.0),
        "bytes_received": safe_float(row.get("bytes_received"), 0.0),
        "connection_count": safe_float(row.get("connection_count"), 0.0),
        "timestamp": normalize_timestamp(row.get("timestamp")),
    }
    return True, "OK", sanitized


def validate_file_extension(filename: str) -> bool:
    """Return True if the file has an allowed extension (.csv)."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() == "csv"
