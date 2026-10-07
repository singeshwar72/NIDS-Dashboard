"""
NIDS Dashboard - Database Manager
Handles SQLite connection, initialization, and all CRUD operations.
Uses parameterized queries exclusively to prevent SQL injection.
"""

import sqlite3
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Thread-safe SQLite database manager."""

    def __init__(self, db_path: str = "nids.db"):
        self.db_path = db_path
        self._ensure_db_directory()
        self.initialize()

    def _ensure_db_directory(self) -> None:
        """Create DB directory if it doesn't exist."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Initialize the database schema from schema.sql."""
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        try:
            with open(schema_path, "r") as f:
                schema_sql = f.read()
            with self.get_connection() as conn:
                conn.executescript(schema_sql)
            logger.info("Database initialized successfully at %s", self.db_path)
        except Exception as e:
            logger.error("Database initialization failed: %s", e)
            raise

    # ------------------------------------------------------------------ #
    # Scan Sessions
    # ------------------------------------------------------------------ #

    def create_session(self, session_name: str, filename: Optional[str] = None) -> int:
        """Create a new scan session and return its ID."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_sessions (session_name, filename) VALUES (?, ?)",
                (session_name, filename),
            )
            return cursor.lastrowid

    def update_session_stats(self, session_id: int, stats: Dict[str, int]) -> None:
        """Update session counters after processing."""
        with self.get_connection() as conn:
            conn.execute(
                """UPDATE scan_sessions SET
                    total_records=?, valid_records=?, invalid_records=?,
                    normal_count=?, suspicious_count=?, high_risk_count=?,
                    critical_count=?, detection_mode=?
                WHERE id=?""",
                (
                    stats.get("total", 0),
                    stats.get("valid", 0),
                    stats.get("invalid", 0),
                    stats.get("normal", 0),
                    stats.get("suspicious", 0),
                    stats.get("high_risk", 0),
                    stats.get("critical", 0),
                    stats.get("detection_mode", "Rule-Based"),
                    session_id,
                ),
            )

    def get_sessions(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Retrieve scan sessions ordered by recency."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_session(self, session_id: int) -> Optional[Dict]:
        """Retrieve a single scan session."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_sessions WHERE id=?", (session_id,)
            ).fetchone()
            return dict(row) if row else None

    def delete_session(self, session_id: int) -> bool:
        """Delete a session and its associated records (CASCADE)."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM scan_sessions WHERE id=?", (session_id,))
            return True

    def count_sessions(self) -> int:
        with self.get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]

    # ------------------------------------------------------------------ #
    # Traffic Records
    # ------------------------------------------------------------------ #

    def insert_traffic_record(self, record: Dict[str, Any]) -> int:
        """Insert a single processed traffic record."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO traffic_records (
                    session_id, timestamp, source_ip, destination_ip,
                    source_port, destination_port, protocol,
                    packet_count, packet_size, duration,
                    bytes_sent, bytes_received, connection_count,
                    packets_per_second, bytes_per_second, byte_ratio,
                    risk_score, classification, attack_type, detection_reason
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    record.get("session_id"),
                    record.get("timestamp"),
                    record["source_ip"],
                    record["destination_ip"],
                    record.get("source_port"),
                    record.get("destination_port"),
                    record.get("protocol"),
                    record.get("packet_count", 0),
                    record.get("packet_size", 0),
                    record.get("duration", 0),
                    record.get("bytes_sent", 0),
                    record.get("bytes_received", 0),
                    record.get("connection_count", 0),
                    record.get("packets_per_second", 0),
                    record.get("bytes_per_second", 0),
                    record.get("byte_ratio", 0),
                    record.get("risk_score", 0),
                    record.get("classification", "NORMAL"),
                    record.get("attack_type", "NONE"),
                    record.get("detection_reason", ""),
                ),
            )
            return cursor.lastrowid

    def bulk_insert_traffic(self, records: List[Dict[str, Any]]) -> int:
        """Bulk insert traffic records; returns count inserted."""
        if not records:
            return 0
        count = 0
        with self.get_connection() as conn:
            for record in records:
                conn.execute(
                    """INSERT INTO traffic_records (
                        session_id, timestamp, source_ip, destination_ip,
                        source_port, destination_port, protocol,
                        packet_count, packet_size, duration,
                        bytes_sent, bytes_received, connection_count,
                        packets_per_second, bytes_per_second, byte_ratio,
                        risk_score, classification, attack_type, detection_reason
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        record.get("session_id"),
                        record.get("timestamp"),
                        record["source_ip"],
                        record["destination_ip"],
                        record.get("source_port"),
                        record.get("destination_port"),
                        record.get("protocol"),
                        record.get("packet_count", 0),
                        record.get("packet_size", 0),
                        record.get("duration", 0),
                        record.get("bytes_sent", 0),
                        record.get("bytes_received", 0),
                        record.get("connection_count", 0),
                        record.get("packets_per_second", 0),
                        record.get("bytes_per_second", 0),
                        record.get("byte_ratio", 0),
                        record.get("risk_score", 0),
                        record.get("classification", "NORMAL"),
                        record.get("attack_type", "NONE"),
                        record.get("detection_reason", ""),
                    ),
                )
                count += 1
        return count

    def get_traffic_records(
        self,
        limit: int = 50,
        offset: int = 0,
        classification: Optional[str] = None,
        protocol: Optional[str] = None,
        search: Optional[str] = None,
        session_id: Optional[int] = None,
    ) -> List[Dict]:
        """Retrieve traffic records with optional filters."""
        params: List[Any] = []
        where_clauses: List[str] = []

        if classification:
            where_clauses.append("classification = ?")
            params.append(classification)
        if protocol:
            where_clauses.append("protocol = ?")
            params.append(protocol.upper())
        if search:
            where_clauses.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        if session_id is not None:
            where_clauses.append("session_id = ?")
            params.append(session_id)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        sql = f"SELECT * FROM traffic_records {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def count_traffic_records(
        self,
        classification: Optional[str] = None,
        protocol: Optional[str] = None,
        search: Optional[str] = None,
        session_id: Optional[int] = None,
    ) -> int:
        params: List[Any] = []
        where_clauses: List[str] = []

        if classification:
            where_clauses.append("classification = ?")
            params.append(classification)
        if protocol:
            where_clauses.append("protocol = ?")
            params.append(protocol.upper())
        if search:
            where_clauses.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        if session_id is not None:
            where_clauses.append("session_id = ?")
            params.append(session_id)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        sql = f"SELECT COUNT(*) FROM traffic_records {where_sql}"

        with self.get_connection() as conn:
            return conn.execute(sql, params).fetchone()[0]

    def get_traffic_record(self, record_id: int) -> Optional[Dict]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM traffic_records WHERE id=?", (record_id,)
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------ #
    # Dashboard Statistics
    # ------------------------------------------------------------------ #

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Compute dashboard summary statistics from actual DB data."""
        with self.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM traffic_records").fetchone()[0]
            normal = conn.execute(
                "SELECT COUNT(*) FROM traffic_records WHERE classification='NORMAL'"
            ).fetchone()[0]
            suspicious = conn.execute(
                "SELECT COUNT(*) FROM traffic_records WHERE classification='SUSPICIOUS'"
            ).fetchone()[0]
            high_risk = conn.execute(
                "SELECT COUNT(*) FROM traffic_records WHERE classification='HIGH RISK'"
            ).fetchone()[0]
            critical = conn.execute(
                "SELECT COUNT(*) FROM traffic_records WHERE classification='CRITICAL'"
            ).fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            new_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status='NEW'"
            ).fetchone()[0]
            return {
                "total": total,
                "normal": normal,
                "suspicious": suspicious,
                "high_risk": high_risk,
                "critical": critical,
                "total_alerts": total_alerts,
                "new_alerts": new_alerts,
            }

    def get_attack_type_distribution(self) -> List[Dict]:
        """Count records grouped by attack type."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """SELECT attack_type, COUNT(*) as count
                   FROM traffic_records
                   WHERE attack_type != 'NONE'
                   GROUP BY attack_type
                   ORDER BY count DESC"""
            ).fetchall()
            return [dict(r) for r in rows]

    def get_alerts_over_time(self, days: int = 7) -> List[Dict]:
        """Return alert counts grouped by day for the last N days."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """SELECT date(created_at) as day, COUNT(*) as count
                   FROM alerts
                   WHERE created_at >= datetime('now', ?)
                   GROUP BY day
                   ORDER BY day ASC""",
                (f"-{days} days",),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_risk_score_distribution(self) -> Dict[str, int]:
        """Return count of records in each risk band."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """SELECT
                    SUM(CASE WHEN risk_score BETWEEN 0 AND 19 THEN 1 ELSE 0 END) as normal,
                    SUM(CASE WHEN risk_score BETWEEN 20 AND 39 THEN 1 ELSE 0 END) as low_risk,
                    SUM(CASE WHEN risk_score BETWEEN 40 AND 59 THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN risk_score BETWEEN 60 AND 79 THEN 1 ELSE 0 END) as high_risk,
                    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical
                   FROM traffic_records"""
            ).fetchone()
            return dict(rows) if rows else {}

    def get_top_source_ips(self, limit: int = 10) -> List[Dict]:
        """Return top source IPs by record count."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """SELECT source_ip, COUNT(*) as count,
                          MAX(risk_score) as max_risk,
                          MAX(classification) as top_class
                   FROM traffic_records
                   GROUP BY source_ip
                   ORDER BY count DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #

    def insert_alert(self, alert: Dict[str, Any]) -> int:
        """Insert a new alert record."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO alerts (
                    session_id, traffic_record_id, timestamp,
                    source_ip, destination_ip, attack_type,
                    severity, risk_score, description, status
                ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    alert.get("session_id"),
                    alert.get("traffic_record_id"),
                    alert.get("timestamp"),
                    alert["source_ip"],
                    alert["destination_ip"],
                    alert.get("attack_type", "UNKNOWN"),
                    alert.get("severity", "HIGH"),
                    alert.get("risk_score", 0),
                    alert.get("description", ""),
                    alert.get("status", "NEW"),
                ),
            )
            return cursor.lastrowid

    def get_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict]:
        """Retrieve alerts with optional filters."""
        params: List[Any] = []
        where_clauses: List[str] = []

        if status:
            where_clauses.append("status = ?")
            params.append(status)
        if severity:
            where_clauses.append("severity = ?")
            params.append(severity)
        if search:
            where_clauses.append("(source_ip LIKE ? OR destination_ip LIKE ? OR attack_type LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        sql = f"SELECT * FROM alerts {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def count_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ) -> int:
        params: List[Any] = []
        where_clauses: List[str] = []

        if status:
            where_clauses.append("status = ?")
            params.append(status)
        if severity:
            where_clauses.append("severity = ?")
            params.append(severity)
        if search:
            where_clauses.append("(source_ip LIKE ? OR destination_ip LIKE ? OR attack_type LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        with self.get_connection() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM alerts {where_sql}", params).fetchone()[0]

    def get_alert(self, alert_id: int) -> Optional[Dict]:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            return dict(row) if row else None

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """Update alert status. Allowed: NEW, ACKNOWLEDGED, RESOLVED."""
        allowed = {"NEW", "ACKNOWLEDGED", "RESOLVED"}
        if status not in allowed:
            return False
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE alerts SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (status, alert_id),
            )
            return True

    def bulk_insert_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        """Bulk insert alerts; returns count inserted."""
        if not alerts:
            return 0
        count = 0
        with self.get_connection() as conn:
            for alert in alerts:
                conn.execute(
                    """INSERT INTO alerts (
                        session_id, traffic_record_id, timestamp,
                        source_ip, destination_ip, attack_type,
                        severity, risk_score, description, status
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        alert.get("session_id"),
                        alert.get("traffic_record_id"),
                        alert.get("timestamp"),
                        alert["source_ip"],
                        alert["destination_ip"],
                        alert.get("attack_type", "UNKNOWN"),
                        alert.get("severity", "HIGH"),
                        alert.get("risk_score", 0),
                        alert.get("description", ""),
                        alert.get("status", "NEW"),
                    ),
                )
                count += 1
        return count
