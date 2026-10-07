"""
Tests for rule_engine, feature_engine, risk_engine, and classifier.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.feature_engine import extract_features, get_feature_names
from detection.rule_engine import run_rules, Thresholds
from detection.risk_engine import calculate_risk, classify_score
from detection.classifier import classify_record


# ------------------------------------------------------------------ #
# Feature Engine Tests
# ------------------------------------------------------------------ #

class TestFeatureEngine:
    BASE_RECORD = {
        "source_ip": "192.168.1.1",
        "destination_ip": "8.8.8.8",
        "source_port": 54321,
        "destination_port": 53,
        "protocol": "DNS",
        "packet_count": 10,
        "packet_size": 200,
        "duration": 2.0,
        "bytes_sent": 1000,
        "bytes_received": 800,
        "connection_count": 5,
        "timestamp": "2024-01-15 08:00:01",
    }

    def test_packets_per_second(self):
        feats = extract_features(self.BASE_RECORD)
        assert feats["packets_per_second"] == pytest.approx(5.0, rel=1e-3)

    def test_bytes_per_second(self):
        feats = extract_features(self.BASE_RECORD)
        assert feats["bytes_per_second"] == pytest.approx(900.0, rel=1e-3)

    def test_byte_ratio(self):
        feats = extract_features(self.BASE_RECORD)
        # bytes_sent(1000) / bytes_received(800)
        assert feats["byte_ratio"] == pytest.approx(1.25, rel=1e-2)

    def test_feature_names_count(self):
        names = get_feature_names()
        assert len(names) >= 10

    def test_port_suspicious_flagged(self):
        rec = dict(self.BASE_RECORD)
        rec["destination_port"] = 3389  # RDP
        feats = extract_features(rec)
        assert feats["port_suspicious"] == 1

    def test_port_suspicious_not_flagged(self):
        rec = dict(self.BASE_RECORD)
        rec["destination_port"] = 12345
        feats = extract_features(rec)
        assert feats["port_suspicious"] == 0

    def test_zero_duration_no_divide_error(self):
        rec = dict(self.BASE_RECORD)
        rec["duration"] = 0
        feats = extract_features(rec)
        assert feats["packets_per_second"] >= 0  # should not raise


# ------------------------------------------------------------------ #
# Rule Engine Tests
# ------------------------------------------------------------------ #

class TestRuleEngine:
    def _make_features(self, **overrides):
        base = {
            "packet_count": 10, "packet_size": 200, "duration": 2.0,
            "bytes_sent": 1000, "bytes_received": 800,
            "connection_count": 2, "source_port": 54321, "destination_port": 53,
            "protocol": "DNS", "packets_per_second": 5.0, "bytes_per_second": 900,
            "byte_ratio": 1.25, "connection_rate": 1.0, "payload_ratio": 1.0,
            "port_suspicious": 0, "is_high_port_src": 1, "is_privileged_dst": 0,
            "protocol_numeric": 6,
        }
        base.update(overrides)
        return base

    def test_no_anomaly_returns_empty(self):
        features = self._make_features()
        result = run_rules(features)
        assert result.total_score == 0.0
        assert len(result.triggered_rules) == 0

    def test_high_connection_count_triggers(self):
        features = self._make_features(connection_count=100)
        result = run_rules(features)
        names = [r.rule_name for r in result.triggered_rules]
        assert "HIGH_CONNECTION_FREQUENCY" in names

    def test_high_packet_rate_triggers(self):
        features = self._make_features(packets_per_second=1000)
        result = run_rules(features)
        names = [r.rule_name for r in result.triggered_rules]
        assert "HIGH_PACKET_RATE" in names

    def test_large_traffic_volume_triggers(self):
        features = self._make_features(bytes_sent=10_000_000, bytes_received=1000)
        result = run_rules(features)
        names = [r.rule_name for r in result.triggered_rules]
        assert "LARGE_TRAFFIC_VOLUME" in names

    def test_suspicious_port_triggers(self):
        features = self._make_features(port_suspicious=1)
        result = run_rules(features)
        names = [r.rule_name for r in result.triggered_rules]
        assert "SUSPICIOUS_DESTINATION_PORT" in names

    def test_score_accumulates(self):
        features = self._make_features(connection_count=100, packets_per_second=1000)
        result = run_rules(features)
        assert result.total_score > 30.0


# ------------------------------------------------------------------ #
# Risk Engine Tests
# ------------------------------------------------------------------ #

class TestRiskEngine:
    def test_classify_normal(self):
        assert classify_score(0) == "NORMAL"
        assert classify_score(19) == "NORMAL"

    def test_classify_low(self):
        assert classify_score(20) == "LOW RISK"
        assert classify_score(39) == "LOW RISK"

    def test_classify_suspicious(self):
        assert classify_score(40) == "SUSPICIOUS"
        assert classify_score(59) == "SUSPICIOUS"

    def test_classify_high(self):
        assert classify_score(60) == "HIGH RISK"
        assert classify_score(79) == "HIGH RISK"

    def test_classify_critical(self):
        assert classify_score(80) == "CRITICAL"
        assert classify_score(100) == "CRITICAL"

    def test_score_clamped(self):
        assert classify_score(150) == "CRITICAL"
        assert classify_score(-10) == "NORMAL"

    def test_risk_result_has_required_keys(self):
        from detection.rule_engine import run_rules
        features = {
            "packet_count": 10, "packet_size": 200, "duration": 2.0,
            "bytes_sent": 1000, "bytes_received": 800,
            "connection_count": 2, "packets_per_second": 5.0,
            "bytes_per_second": 900, "byte_ratio": 1.25,
            "connection_rate": 1.0, "port_suspicious": 0,
            "is_privileged_dst": 0, "is_high_port_src": 1,
        }
        detection = run_rules(features)
        result = calculate_risk(detection, features)
        assert "risk_score" in result
        assert "classification" in result
        assert "reasons" in result
        assert "attack_type" in result
        assert isinstance(result["reasons"], list)


# ------------------------------------------------------------------ #
# Classifier Tests
# ------------------------------------------------------------------ #

class TestClassifier:
    BASE_RECORD = {
        "source_ip": "192.168.1.1",
        "destination_ip": "8.8.8.8",
        "source_port": 54321,
        "destination_port": 53,
        "protocol": "DNS",
        "packet_count": 10,
        "packet_size": 200,
        "duration": 2.0,
        "bytes_sent": 1000,
        "bytes_received": 800,
        "connection_count": 2,
        "timestamp": "2024-01-15 08:00:01",
    }

    def test_classify_returns_dict(self):
        result = classify_record(self.BASE_RECORD)
        assert isinstance(result, dict)

    def test_classify_has_required_fields(self):
        result = classify_record(self.BASE_RECORD)
        for key in ("risk_score", "classification", "attack_type", "detection_mode"):
            assert key in result, f"Missing key: {key}"

    def test_classify_normal_traffic(self):
        result = classify_record(self.BASE_RECORD)
        assert result["classification"] in ("NORMAL", "LOW RISK", "SUSPICIOUS", "HIGH RISK", "CRITICAL")

    def test_classify_high_risk_traffic(self):
        record = dict(self.BASE_RECORD)
        record["connection_count"] = 300
        record["packet_count"] = 5000
        record["bytes_sent"] = 60_000_000
        result = classify_record(record)
        assert result["risk_score"] > 40.0

    def test_classify_works_without_ml(self):
        result = classify_record(self.BASE_RECORD, ml_predictor=None)
        assert result["detection_mode"] == "Rule-Based"

    def test_detection_mode_ml(self):
        def fake_ml(features):
            return "HIGH_RISK"
        result = classify_record(self.BASE_RECORD, ml_predictor=fake_ml)
        assert result["detection_mode"] == "Rule-Based + ML"
