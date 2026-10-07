"""
NIDS Dashboard - Rule-Based Detection Engine
Analyzes extracted features and returns rule match results.

Each rule:
  - Is a pure function of the feature dict.
  - Returns a RuleResult with detected flag, name, severity, explanation, score.
  - Does NOT generate attacks. It only analyzes supplied traffic data.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Data Structures
# ------------------------------------------------------------------ #

@dataclass
class RuleResult:
    rule_name: str
    detected: bool
    severity: str          # INFO | LOW | MEDIUM | HIGH | CRITICAL
    score_contribution: float
    explanation: str
    attack_type: str = "UNKNOWN"


@dataclass
class DetectionResult:
    triggered_rules: List[RuleResult] = field(default_factory=list)
    total_score: float = 0.0
    attack_types: List[str] = field(default_factory=list)
    summary: str = "No anomalies detected"

    def add_rule(self, result: RuleResult) -> None:
        if result.detected:
            self.triggered_rules.append(result)
            self.total_score += result.score_contribution
            if result.attack_type and result.attack_type != "UNKNOWN":
                if result.attack_type not in self.attack_types:
                    self.attack_types.append(result.attack_type)

    def get_primary_attack_type(self) -> str:
        if not self.attack_types:
            return "NONE"
        # Return attack type of highest-scoring rule
        best = max(self.triggered_rules, key=lambda r: r.score_contribution, default=None)
        return best.attack_type if best else self.attack_types[0]

    def get_reasons(self) -> List[str]:
        return [r.explanation for r in self.triggered_rules]


# ------------------------------------------------------------------ #
# Thresholds (tunable)
# ------------------------------------------------------------------ #

class Thresholds:
    # HIGH_CONNECTION_FREQUENCY
    HIGH_CONN_COUNT = 50
    VERY_HIGH_CONN_COUNT = 200

    # HIGH_PACKET_RATE
    HIGH_PKT_RATE = 500       # packets/sec
    VERY_HIGH_PKT_RATE = 2000

    # LARGE_TRAFFIC_VOLUME
    HIGH_BYTES = 5_000_000    # 5 MB
    VERY_HIGH_BYTES = 50_000_000  # 50 MB

    # ABNORMAL_BYTE_RATIO
    HIGH_RATIO = 100.0        # sent >> received (exfiltration indicator)
    LOW_RATIO = 0.01          # received >> sent (flood indicator)

    # SUSPICIOUS_DESTINATION_PORT
    # Handled via port_suspicious feature

    # FAST_CONNECTION_RATE
    HIGH_CONN_RATE = 10.0     # connections/sec

    # SMALL_PACKET_ANOMALY (possible scanning)
    SMALL_PACKET_SIZE = 64    # bytes

    # LARGE_PACKET_ANOMALY
    JUMBO_PACKET_SIZE = 9000  # bytes

    # HIGH_BYTES_PER_SECOND
    HIGH_BPS = 1_000_000      # 1 MB/s
    VERY_HIGH_BPS = 10_000_000


# ------------------------------------------------------------------ #
# Individual Rules
# ------------------------------------------------------------------ #

def rule_high_connection_frequency(features: Dict[str, Any]) -> RuleResult:
    """
    Rule: HIGH_CONNECTION_FREQUENCY
    Detects unusually high number of connections from a single source.
    Indicator: Scanning, DoS reconnaissance, botnet activity.
    """
    cc = features.get("connection_count", 0)
    if cc >= Thresholds.VERY_HIGH_CONN_COUNT:
        return RuleResult(
            rule_name="HIGH_CONNECTION_FREQUENCY",
            detected=True,
            severity="CRITICAL",
            score_contribution=35.0,
            explanation=f"Extremely high connection count ({cc:.0f}) detected — possible DoS/scanning.",
            attack_type="RECONNAISSANCE",
        )
    if cc >= Thresholds.HIGH_CONN_COUNT:
        return RuleResult(
            rule_name="HIGH_CONNECTION_FREQUENCY",
            detected=True,
            severity="HIGH",
            score_contribution=20.0,
            explanation=f"High connection count ({cc:.0f}) detected — possible reconnaissance.",
            attack_type="RECONNAISSANCE",
        )
    return RuleResult(
        rule_name="HIGH_CONNECTION_FREQUENCY",
        detected=False,
        severity="INFO",
        score_contribution=0.0,
        explanation="Connection count within normal range.",
    )


def rule_high_packet_rate(features: Dict[str, Any]) -> RuleResult:
    """
    Rule: HIGH_PACKET_RATE
    Detects abnormally high packets-per-second.
    Indicator: Flood attacks or malformed traffic burst.
    """
    pps = features.get("packets_per_second", 0)
    if pps >= Thresholds.VERY_HIGH_PKT_RATE:
        return RuleResult(
            rule_name="HIGH_PACKET_RATE",
            detected=True,
            severity="CRITICAL",
            score_contribution=30.0,
            explanation=f"Extremely high packet rate ({pps:.1f} pkt/s) — possible flood attack.",
            attack_type="FLOOD",
        )
    if pps >= Thresholds.HIGH_PKT_RATE:
        return RuleResult(
            rule_name="HIGH_PACKET_RATE",
            detected=True,
            severity="HIGH",
            score_contribution=18.0,
            explanation=f"High packet rate ({pps:.1f} pkt/s) — abnormal burst detected.",
            attack_type="FLOOD",
        )
    return RuleResult(
        rule_name="HIGH_PACKET_RATE",
        detected=False,
        severity="INFO",
        score_contribution=0.0,
        explanation="Packet rate within normal range.",
    )


def rule_large_traffic_volume(features: Dict[str, Any]) -> RuleResult:
    """
    Rule: LARGE_TRAFFIC_VOLUME
    Detects unusually large total bytes transferred.
    Indicator: Data exfiltration or large payload attack.
    """
    total_bytes = features.get("bytes_sent", 0) + features.get("bytes_received", 0)
    if total_bytes >= Thresholds.VERY_HIGH_BYTES:
        return RuleResult(
            rule_name="LARGE_TRAFFIC_VOLUME",
            detected=True,
            severity="CRITICAL",
            score_contribution=30.0,
            explanation=f"Extremely large traffic volume ({total_bytes/1e6:.1f} MB) — possible data exfiltration.",
            attack_type="EXFILTRATION",
        )
    if total_bytes >= Thresholds.HIGH_BYTES:
        return RuleResult(
            rule_name="LARGE_TRAFFIC_VOLUME",
            detected=True,
            severity="HIGH",
            score_contribution=15.0,
            explanation=f"Large traffic volume ({total_bytes/1e6:.2f} MB) — above normal threshold.",
            attack_type="EXFILTRATION",
        )
    return RuleResult(
        rule_name="LARGE_TRAFFIC_VOLUME",
        detected=False,
        severity="INFO",
        score_contribution=0.0,
        explanation="Traffic volume within normal range.",
    )


def rule_abnormal_byte_ratio(features: Dict[str, Any]) -> RuleResult:
    """
    Rule: ABNORMAL_BYTE_RATIO
    Detects asymmetric sent/received byte ratios.
    High ratio (sent >> received): possible exfiltration.
    Low ratio (received >> sent): possible flood or download attack.
    """
    ratio = features.get("byte_ratio", 1.0)
    if ratio >= Thresholds.HIGH_RATIO:
        return RuleResult(
            rule_name="ABNORMAL_BYTE_RATIO",
            detected=True,
            severity="HIGH",
            score_contribution=20.0,
            explanation=f"Extremely high byte ratio ({ratio:.1f}): bytes_sent >> bytes_received — possible exfiltration.",
            attack_type="EXFILTRATION",
        )
    if ratio <= Thresholds.LOW_RATIO and ratio > 0:
        return RuleResult(
            rule_name="ABNORMAL_BYTE_RATIO",
            detected=True,
            severity="MEDIUM",
            score_contribution=12.0,
            explanation=f"Low byte ratio ({ratio:.4f}): bytes_received >> bytes_sent — possible inbound flood.",
            attack_type="FLOOD",
        )
    return RuleResult(
        rule_name="ABNORMAL_BYTE_RATIO",
        detected=False,
        severity="INFO",
        score_contribution=0.0,
        explanation="Byte ratio within normal range.",
    )


def rule_suspicious_destination_port(features: Dict[str, Any]) -> RuleResult:
    """
    Rule: SUSPICIOUS_DESTINATION_PORT
    Detects connections targeting known attack-pattern destination ports.
    Indicator: Remote access tools, common exploitation ports.
    """
    if features.get("port_suspicious", 0) == 1:
        dst_port = features.get("destination_port", 0)
        return RuleResult(
            rule_name="SUSPICIOUS_DESTINATION_PORT",
            detected=True,
            severity="MEDIUM",
            score_contribution=10.0,
            explanation=f"Connection targets suspicious port {dst_port} — commonly associated with remote access or services.",
            attack_type="SUSPICIOUS_PORT",
        )
    return RuleResult(
        rule_name="SUSPICIOUS_DESTINATION_PORT",
        detected=False,
        severity="INFO",
        score_contribution=0.0,
        explanation="Destination port not in suspicious list.",
    )


def rule_fast_connection_rate(features: Dict[str, Any]) -> RuleResult:
    """
    Rule: FAST_CONNECTION_RATE
    Detects a high rate of connections per second.
    Indicator: Port scanning or SYN flood.
    """
    rate = features.get("connection_rate", 0)
    if rate >= Thresholds.HIGH_CONN_RATE:
        return RuleResult(
            rule_name="FAST_CONNECTION_RATE",
            detected=True,
            severity="HIGH",
            score_contribution=22.0,
            explanation=f"High connection rate ({rate:.2f} conn/s) — possible port scan or SYN flood.",
            attack_type="PORT_SCAN",
        )
    return RuleResult(
        rule_name="FAST_CONNECTION_RATE",
        detected=False,
        severity="INFO",
        score_contribution=0.0,
        explanation="Connection rate within normal range.",
    )


def rule_small_packet_anomaly(features: Dict[str, Any]) -> RuleResult:
    """
    Rule: SMALL_PACKET_ANOMALY
    Very small packets with high count may indicate scanning probes.
    """
    ps = features.get("packet_size", 0)
    pc = features.get("packet_count", 0)
    if ps > 0 and ps < Thresholds.SMALL_PACKET_SIZE and pc > 100:
        return RuleResult(
            rule_name="SMALL_PACKET_ANOMALY",
            detected=True,
            severity="MEDIUM",
            score_contribution=10.0,
            explanation=f"Many small packets (size={ps:.0f} bytes, count={pc:.0f}) — possible probe/scan.",
            attack_type="SCANNING",
        )
    return RuleResult(
        rule_name="SMALL_PACKET_ANOMALY",
        detected=False,
        severity="INFO",
        score_contribution=0.0,
        explanation="Packet size within normal range.",
    )


def rule_high_bandwidth(features: Dict[str, Any]) -> RuleResult:
    """
    Rule: HIGH_BANDWIDTH
    Detects high bytes-per-second throughput.
    Indicator: DDoS amplification or large-scale data transfer.
    """
    bps = features.get("bytes_per_second", 0)
    if bps >= Thresholds.VERY_HIGH_BPS:
        return RuleResult(
            rule_name="HIGH_BANDWIDTH",
            detected=True,
            severity="CRITICAL",
            score_contribution=28.0,
            explanation=f"Extremely high bandwidth ({bps/1e6:.1f} MB/s) — possible DDoS amplification.",
            attack_type="DDOS",
        )
    if bps >= Thresholds.HIGH_BPS:
        return RuleResult(
            rule_name="HIGH_BANDWIDTH",
            detected=True,
            severity="HIGH",
            score_contribution=16.0,
            explanation=f"High bandwidth usage ({bps/1e6:.2f} MB/s) — above normal threshold.",
            attack_type="DDOS",
        )
    return RuleResult(
        rule_name="HIGH_BANDWIDTH",
        detected=False,
        severity="INFO",
        score_contribution=0.0,
        explanation="Bandwidth within normal range.",
    )


# ------------------------------------------------------------------ #
# Rule Engine Entry Point
# ------------------------------------------------------------------ #

ALL_RULES = [
    rule_high_connection_frequency,
    rule_high_packet_rate,
    rule_large_traffic_volume,
    rule_abnormal_byte_ratio,
    rule_suspicious_destination_port,
    rule_fast_connection_rate,
    rule_small_packet_anomaly,
    rule_high_bandwidth,
]


def run_rules(features: Dict[str, Any]) -> DetectionResult:
    """
    Run all detection rules against the given feature dict.
    Returns a DetectionResult aggregating all triggered rules.
    """
    result = DetectionResult()
    for rule_fn in ALL_RULES:
        try:
            rule_result = rule_fn(features)
            result.add_rule(rule_result)
        except Exception as e:
            logger.warning("Rule %s raised exception: %s", rule_fn.__name__, e)

    if result.triggered_rules:
        rule_names = [r.rule_name for r in result.triggered_rules]
        result.summary = f"Detected: {', '.join(rule_names)}"
    else:
        result.summary = "No anomalies detected in supplied traffic record"

    return result
