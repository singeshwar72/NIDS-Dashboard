"""
NIDS Dashboard - Traffic Service
Handles CSV ingestion, validation, feature extraction, and detection pipeline.
"""

import io
import logging
import os
from datetime import datetime
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

import pandas as pd

from detection.validators import (
    validate_csv_columns,
    validate_row,
    validate_file_extension,
)
from detection.classifier import classify_record
from database.database import DatabaseManager

logger = logging.getLogger(__name__)

MAX_ROWS = 50_000  # safety limit per upload


def process_csv_file(
    file_obj,
    filename: str,
    db: DatabaseManager,
    session_name: Optional[str] = None,
    ml_predictor=None,
) -> Dict[str, Any]:
    """
    Full pipeline: read CSV -> validate -> classify -> store -> return summary.

    Args:
        file_obj   : file-like object (binary or text)
        filename   : original filename (for extension check)
        db         : DatabaseManager instance
        session_name: human-readable session label
        ml_predictor: optional ML predict function

    Returns:
        Summary dict with counts and session_id.
    """
    # ---- Validate extension ----
    if not validate_file_extension(filename):
        return {
            "success": False,
            "error": "Only CSV files are supported.",
        }

    # ---- Read CSV ----
    try:
        if hasattr(file_obj, "read"):
            raw = file_obj.read()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            df = pd.read_csv(io.StringIO(raw), dtype=str, keep_default_na=False)
        else:
            df = pd.read_csv(file_obj, dtype=str, keep_default_na=False)
    except Exception as e:
        logger.error("CSV parse error: %s", e)
        return {"success": False, "error": f"Failed to parse CSV: {str(e)}"}

    if df.empty:
        return {"success": False, "error": "The CSV file is empty."}

    # ---- Validate columns ----
    df.columns = [c.strip().lower() for c in df.columns]
    col_ok, col_msg = validate_csv_columns(list(df.columns))
    if not col_ok:
        return {"success": False, "error": col_msg}

    total_rows = min(len(df), MAX_ROWS)
    df = df.iloc[:total_rows]

    # ---- Create DB session ----
    sname = session_name or f"Upload: {filename} @ {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    session_id = db.create_session(sname, filename)

    # ---- Process rows ----
    valid_records: List[Dict] = []
    alert_records: List[Dict] = []
    invalid_count = 0
    counters = {"NORMAL": 0, "LOW RISK": 0, "SUSPICIOUS": 0, "HIGH RISK": 0, "CRITICAL": 0}
    detection_mode = "Rule-Based"

    for _, row in df.iterrows():
        row_dict = row.to_dict()
        is_valid, reason, sanitized = validate_row(row_dict)
        if not is_valid:
            invalid_count += 1
            logger.debug("Invalid row skipped: %s", reason)
            continue

        # Run full classification pipeline
        classified = classify_record(sanitized, ml_predictor=ml_predictor)
        classified["session_id"] = session_id

        if classified.get("detection_mode") == "Rule-Based + ML":
            detection_mode = "Rule-Based + ML"

        valid_records.append(classified)
        cls = classified.get("classification", "NORMAL")
        if cls in counters:
            counters[cls] += 1
        else:
            counters["NORMAL"] += 1

        # Generate alert for HIGH RISK or CRITICAL
        if cls in ("HIGH RISK", "CRITICAL"):
            alert = {
                "session_id": session_id,
                "timestamp": classified.get("timestamp"),
                "source_ip": classified["source_ip"],
                "destination_ip": classified["destination_ip"],
                "attack_type": classified.get("attack_type", "UNKNOWN"),
                "severity": "CRITICAL" if cls == "CRITICAL" else "HIGH",
                "risk_score": classified.get("risk_score", 0),
                "description": classified.get("detection_reason", ""),
                "status": "NEW",
            }
            alert_records.append(alert)

    # ---- Bulk insert ----
    inserted = 0
    if valid_records:
        inserted = db.bulk_insert_traffic(valid_records)

    alert_inserted = 0
    if alert_records:
        # Link traffic_record_id after bulk insert
        db.bulk_insert_alerts(alert_records)
        alert_inserted = len(alert_records)

    # ---- Update session stats ----
    db.update_session_stats(
        session_id,
        {
            "total": total_rows,
            "valid": inserted,
            "invalid": invalid_count,
            "normal": counters.get("NORMAL", 0),
            "suspicious": counters.get("SUSPICIOUS", 0),
            "high_risk": counters.get("HIGH RISK", 0),
            "critical": counters.get("CRITICAL", 0),
            "detection_mode": detection_mode,
        },
    )

    return {
        "success": True,
        "session_id": session_id,
        "filename": filename,
        "total_rows": total_rows,
        "valid_rows": inserted,
        "invalid_rows": invalid_count,
        "normal": counters.get("NORMAL", 0),
        "low_risk": counters.get("LOW RISK", 0),
        "suspicious": counters.get("SUSPICIOUS", 0),
        "high_risk": counters.get("HIGH RISK", 0),
        "critical": counters.get("CRITICAL", 0),
        "alerts_generated": alert_inserted,
        "detection_mode": detection_mode,
    }


def load_demo_dataset(demo_path: str, db: DatabaseManager, ml_predictor=None) -> Dict[str, Any]:
    """Load and process the synthetic demo CSV."""
    if not os.path.exists(demo_path):
        return {"success": False, "error": "Demo dataset not found."}
    try:
        with open(demo_path, "rb") as f:
            return process_csv_file(f, "sample_traffic.csv", db, "Demo Dataset", ml_predictor)
    except Exception as e:
        logger.error("Demo dataset error: %s", e)
        return {"success": False, "error": str(e)}
