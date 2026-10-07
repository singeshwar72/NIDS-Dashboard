"""
Tests for risk_engine.py (additional edge-case tests).
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.risk_engine import calculate_risk, classify_score
from detection.rule_engine import run_rules, DetectionResult


def make_clean_features():
    return {
        "packet_count": 10, "packet_size": 200, "duration": 2.0,
        "bytes_sent": 1000, "bytes_received": 800,
        "connection_count": 2, "packets_per_second": 5.0,
        "bytes_per_second": 900, "byte_ratio": 1.25,
        "connection_rate": 1.0, "port_suspicious": 0,
        "is_privileged_dst": 0, "is_high_port_src": 1,
        "payload_ratio": 1.0,
    }


def test_no_detections_gives_normal():
    features = make_clean_features()
    det = run_rules(features)
    result = calculate_risk(det, features)
    assert result["risk_score"] < 20
    assert result["classification"] == "NORMAL"


def test_critical_threshold_met():
    features = make_clean_features()
    features["connection_count"] = 500
    features["packets_per_second"] = 3000
    features["bytes_sent"] = 100_000_000
    det = run_rules(features)
    result = calculate_risk(det, features)
    assert result["risk_score"] >= 80
    assert result["classification"] == "CRITICAL"


def test_reasons_list_not_empty_on_detection():
    features = make_clean_features()
    features["connection_count"] = 100
    det = run_rules(features)
    result = calculate_risk(det, features)
    assert len(result["reasons"]) > 0


def test_deterministic_scoring():
    """Same input always produces same output."""
    features = make_clean_features()
    features["packets_per_second"] = 600
    det1 = run_rules(features)
    det2 = run_rules(features)
    r1 = calculate_risk(det1, features)
    r2 = calculate_risk(det2, features)
    assert r1["risk_score"] == r2["risk_score"]


def test_score_not_negative():
    features = make_clean_features()
    det = DetectionResult()
    result = calculate_risk(det, features)
    assert result["risk_score"] >= 0.0


def test_score_not_above_100():
    features = make_clean_features()
    features["connection_count"] = 99999
    features["packets_per_second"] = 99999
    features["bytes_sent"] = 999_999_999
    det = run_rules(features)
    result = calculate_risk(det, features)
    assert result["risk_score"] <= 100.0
