"""
NIDS Dashboard - Feature Engineering
Extracts deterministic numeric features from sanitized traffic records.
Each feature is documented with its purpose and calculation method.
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Small epsilon to prevent division by zero
_EPS = 1e-9


def extract_features(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and compute all detection features from a validated traffic record.

    Features computed:
    - packets_per_second  : packet_count / max(duration, eps)
    - bytes_per_second    : (bytes_sent + bytes_received) / max(duration, eps)
    - byte_ratio          : bytes_sent / max(bytes_received, eps)
    - port_suspicious     : 1 if destination port in known attack-pattern ports
    - protocol_numeric    : integer encoding of protocol
    - is_high_port_src    : 1 if source port >= 1024
    - is_privileged_dst   : 1 if destination port < 1024
    - connection_rate     : connection_count / max(duration, eps)
    - payload_ratio       : bytes_sent / max(packet_count * packet_size, eps)
    """
    pc = float(record.get("packet_count", 0) or 0)
    ps = float(record.get("packet_size", 0) or 0)
    dur = float(record.get("duration", 0) or 0)
    bs = float(record.get("bytes_sent", 0) or 0)
    br = float(record.get("bytes_received", 0) or 0)
    cc = float(record.get("connection_count", 0) or 0)
    src_port = int(record.get("source_port", 0) or 0)
    dst_port = int(record.get("destination_port", 0) or 0)
    protocol = str(record.get("protocol", "OTHER")).upper()

    # -- Core computed features --

    # packets_per_second: high values indicate flooding
    packets_per_second = pc / max(dur, _EPS)

    # bytes_per_second: high volume may indicate data exfiltration or flood
    bytes_per_second = (bs + br) / max(dur, _EPS)

    # byte_ratio: severely asymmetric ratios may indicate exfiltration or C&C
    byte_ratio = bs / max(br, _EPS)

    # connection_rate: many connections in short time = scanning
    connection_rate = cc / max(dur, _EPS)

    # payload_ratio: actual bytes vs expected (packet_count * packet_size)
    expected_bytes = pc * ps
    payload_ratio = (bs + br) / max(expected_bytes, _EPS) if expected_bytes > 0 else 0.0

    # -- Port-based features --

    # Known attack-pattern destination ports (not exhaustive; for demo use)
    SUSPICIOUS_PORTS = {
        22, 23, 3389, 445, 135, 139, 443, 80,
        8080, 8443, 1433, 3306, 5432, 6379, 27017,
        53, 161, 500, 4444, 5555, 6666, 7777, 8888, 9999,
    }

    port_suspicious = 1 if dst_port in SUSPICIOUS_PORTS else 0
    is_high_port_src = 1 if src_port >= 1024 else 0
    is_privileged_dst = 1 if 0 < dst_port < 1024 else 0

    # -- Protocol encoding --
    PROTOCOL_MAP = {
        "TCP": 1, "UDP": 2, "ICMP": 3, "HTTP": 4,
        "HTTPS": 5, "DNS": 6, "FTP": 7, "SSH": 8,
        "SMTP": 9, "OTHER": 0,
    }
    protocol_numeric = PROTOCOL_MAP.get(protocol, 0)

    # -- Assemble feature dict --
    features = {
        # Original fields (passed through)
        "packet_count": pc,
        "packet_size": ps,
        "duration": dur,
        "bytes_sent": bs,
        "bytes_received": br,
        "connection_count": cc,
        "source_port": src_port,
        "destination_port": dst_port,
        # Computed features
        "packets_per_second": round(packets_per_second, 4),
        "bytes_per_second": round(bytes_per_second, 4),
        "byte_ratio": round(byte_ratio, 4),
        "connection_rate": round(connection_rate, 4),
        "payload_ratio": round(payload_ratio, 4),
        "port_suspicious": port_suspicious,
        "is_high_port_src": is_high_port_src,
        "is_privileged_dst": is_privileged_dst,
        "protocol_numeric": protocol_numeric,
    }
    return features


def get_feature_names() -> list:
    """Return the ordered list of ML feature column names."""
    return [
        "packet_count",
        "packet_size",
        "duration",
        "bytes_sent",
        "bytes_received",
        "connection_count",
        "packets_per_second",
        "bytes_per_second",
        "byte_ratio",
        "connection_rate",
        "payload_ratio",
        "port_suspicious",
        "is_high_port_src",
        "is_privileged_dst",
        "protocol_numeric",
    ]
