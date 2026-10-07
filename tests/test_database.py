"""
Tests for database.py (DatabaseManager).
"""
import pytest
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def db(tmp_path):
    """Create a temp database for testing."""
    from database.database import DatabaseManager
    db_path = str(tmp_path / "test_nids.db")
    manager = DatabaseManager(db_path)
    yield manager


class TestDatabaseInit:
    def test_tables_created(self, db):
        with db.get_connection() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            names = {t[0] for t in tables}
        assert "traffic_records" in names
        assert "alerts" in names
        assert "scan_sessions" in names


class TestScanSessions:
    def test_create_session(self, db):
        sid = db.create_session("Test Session", "test.csv")
        assert isinstance(sid, int)
        assert sid > 0

    def test_get_session(self, db):
        sid = db.create_session("Test", "file.csv")
        session = db.get_session(sid)
        assert session is not None
        assert session["session_name"] == "Test"

    def test_update_session_stats(self, db):
        sid = db.create_session("Test")
        db.update_session_stats(sid, {
            "total": 100, "valid": 90, "invalid": 10,
            "normal": 70, "suspicious": 10, "high_risk": 5, "critical": 5,
            "detection_mode": "Rule-Based",
        })
        session = db.get_session(sid)
        assert session["total_records"] == 100
        assert session["normal_count"] == 70

    def test_delete_session(self, db):
        sid = db.create_session("To Delete")
        db.delete_session(sid)
        assert db.get_session(sid) is None

    def test_count_sessions(self, db):
        db.create_session("S1")
        db.create_session("S2")
        assert db.count_sessions() >= 2


class TestTrafficRecords:
    def _record(self, session_id=1):
        return {
            "session_id": session_id,
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "source_port": 54321,
            "destination_port": 53,
            "protocol": "DNS",
            "packet_count": 5,
            "packet_size": 60,
            "duration": 0.5,
            "bytes_sent": 300,
            "bytes_received": 280,
            "connection_count": 2,
            "packets_per_second": 10,
            "bytes_per_second": 1160,
            "byte_ratio": 1.07,
            "risk_score": 5.0,
            "classification": "NORMAL",
            "attack_type": "NONE",
            "detection_reason": "",
            "timestamp": "2024-01-15 08:00:01",
        }

    def test_insert_traffic_record(self, db):
        sid = db.create_session("Test")
        rec = self._record(sid)
        rid = db.insert_traffic_record(rec)
        assert rid > 0

    def test_get_traffic_record(self, db):
        sid = db.create_session("Test")
        rec = self._record(sid)
        rid = db.insert_traffic_record(rec)
        fetched = db.get_traffic_record(rid)
        assert fetched is not None
        assert fetched["source_ip"] == "192.168.1.10"

    def test_get_traffic_records_filter(self, db):
        sid = db.create_session("Test")
        rec = self._record(sid)
        db.insert_traffic_record(rec)
        records = db.get_traffic_records(classification="NORMAL")
        assert len(records) >= 1

    def test_dashboard_stats_correct(self, db):
        sid = db.create_session("Test")
        rec = self._record(sid)
        rec["classification"] = "CRITICAL"
        rec["risk_score"] = 85
        db.insert_traffic_record(rec)
        stats = db.get_dashboard_stats()
        assert stats["critical"] >= 1
        assert stats["total"] >= 1


class TestAlerts:
    def _alert(self, session_id=1):
        return {
            "session_id": session_id,
            "source_ip": "10.0.0.5",
            "destination_ip": "192.168.1.100",
            "attack_type": "RECONNAISSANCE",
            "severity": "HIGH",
            "risk_score": 72.0,
            "description": "High connection count detected",
            "status": "NEW",
            "timestamp": "2024-01-15 08:03:00",
        }

    def test_insert_alert(self, db):
        sid = db.create_session("Test")
        alert = self._alert(sid)
        aid = db.insert_alert(alert)
        assert aid > 0

    def test_get_alert(self, db):
        sid = db.create_session("Test")
        aid = db.insert_alert(self._alert(sid))
        fetched = db.get_alert(aid)
        assert fetched is not None
        assert fetched["severity"] == "HIGH"

    def test_update_alert_status(self, db):
        sid = db.create_session("Test")
        aid = db.insert_alert(self._alert(sid))
        db.update_alert_status(aid, "ACKNOWLEDGED")
        fetched = db.get_alert(aid)
        assert fetched["status"] == "ACKNOWLEDGED"

    def test_update_alert_invalid_status(self, db):
        sid = db.create_session("Test")
        aid = db.insert_alert(self._alert(sid))
        result = db.update_alert_status(aid, "INVALID_STATUS")
        assert result is False

    def test_get_alerts_filter_status(self, db):
        sid = db.create_session("Test")
        db.insert_alert(self._alert(sid))
        alerts = db.get_alerts(status="NEW")
        assert len(alerts) >= 1
        for a in alerts:
            assert a["status"] == "NEW"
