"""
NIDS Dashboard - Risk Scoring Engine
Calculates a deterministic risk score (0-100) from detection results and features.
Classification bands match the project specification.
"""

import logging
from typing import Any, Dict, List

from detection.rule_engine import DetectionResult

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Classification Bands
# ------------------------------------------------------------------ #

BANDS = [
    (0, 19, "NORMAL"),
    (20, 39, "LOW RISK"),
    (40, 59, "SUSPICIOUS"),
    (60, 79, "HIGH RISK"),
    (80, 100, "CRITICAL"),
]


def classify_score(score: float) -> str:
    """Map a numeric score to its classification label."""
    clamped = max(0.0, min(100.0, score))
    for lo, hi, label in BANDS:
        if lo <= clamped <= hi:
            return label
    return "CRITICAL"


# ------------------------------------------------------------------ #
# Risk Engine
# ------------------------------------------------------------------ #

def calculate_risk(
    detection_result: DetectionResult,
    features: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calculate a deterministic risk score from:
    1. Rule-based score contributions (primary)
    2. Feature amplifiers (secondary modifiers for edge cases)

    Score is clamped to [0, 100].
    Never uses random numbers.

    Returns:
        {
            "risk_score": float,
            "classification": str,
            "reasons": List[str],
            "attack_type": str,
        }
    """
    base_score: float = detection_result.total_score

    # ---- Feature-based amplifiers ----
    # These add small bonuses on top of rule scores for borderline cases.

    amplifiers: List[str] = []

    pps = features.get("packets_per_second", 0)
    bps = features.get("bytes_per_second", 0)
    ratio = features.get("byte_ratio", 1.0)
    cc = features.get("connection_count", 0)
    cr = features.get("connection_rate", 0)
    ps = features.get("packet_size", 0)

    # Near-threshold bonus for packets per second (200-499 range)
    if 200 <= pps < 500:
        base_score += 5.0
        amplifiers.append(f"Elevated packet rate ({pps:.0f} pkt/s)")

    # Near-threshold bonus for bandwidth (500KB - 1MB/s)
    if 500_000 <= bps < 1_000_000:
        base_score += 4.0
        amplifiers.append(f"Elevated bandwidth ({bps/1000:.0f} KB/s)")

    # Moderate asymmetric byte ratio
    if 10.0 <= ratio < 100.0:
        base_score += 5.0
        amplifiers.append(f"Asymmetric byte ratio ({ratio:.1f})")

    # Moderate connection count (25-49)
    if 25 <= cc < 50:
        base_score += 4.0
        amplifiers.append(f"Moderate connection count ({cc:.0f})")

    # Privileged destination port with high connection rate
    if features.get("is_privileged_dst", 0) == 1 and cr >= 1.0:
        base_score += 5.0
        amplifiers.append(f"Privileged dst port with conn rate {cr:.2f}")

    # Suspicious port with multiple indicators
    if features.get("port_suspicious", 0) == 1 and len(detection_result.triggered_rules) >= 2:
        base_score += 5.0
        amplifiers.append("Multiple rules triggered on suspicious port")

    # Clamp final score
    final_score = max(0.0, min(100.0, base_score))
    classification = classify_score(final_score)

    # Build reasons list
    rule_reasons = detection_result.get_reasons()
    all_reasons = rule_reasons + amplifiers

    if not all_reasons:
        all_reasons = ["Traffic pattern within normal parameters"]

    return {
        "risk_score": round(final_score, 2),
        "classification": classification,
        "reasons": all_reasons,
        "attack_type": detection_result.get_primary_attack_type(),
    }
