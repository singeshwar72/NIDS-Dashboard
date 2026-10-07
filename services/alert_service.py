"""
NIDS Dashboard - Alert Service
Provides alert management operations on top of the database layer.
"""

import logging
from typing import Any, Dict, List, Optional

from database.database import DatabaseManager

logger = logging.getLogger(__name__)

VALID_STATUSES = {"NEW", "ACKNOWLEDGED", "RESOLVED"}


def get_alerts(
    db: DatabaseManager,
    page: int = 1,
    page_size: int = 50,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Return paginated alert list with total count."""
    if page < 1:
        page = 1
    offset = (page - 1) * page_size

    alerts = db.get_alerts(limit=page_size, offset=offset, status=status, severity=severity, search=search)
    total = db.count_alerts(status=status, severity=severity, search=search)

    return {
        "alerts": alerts,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


def update_alert_status(db: DatabaseManager, alert_id: int, new_status: str) -> Dict[str, Any]:
    """Update alert status with validation."""
    status = str(new_status).upper().strip()
    if status not in VALID_STATUSES:
        return {
            "success": False,
            "error": f"Invalid status. Allowed: {', '.join(sorted(VALID_STATUSES))}",
        }

    alert = db.get_alert(alert_id)
    if not alert:
        return {"success": False, "error": "Alert not found."}

    db.update_alert_status(alert_id, status)
    return {"success": True, "alert_id": alert_id, "new_status": status}


def get_alert_summary(db: DatabaseManager) -> Dict[str, Any]:
    """Return a quick summary of alert counts by status."""
    all_alerts = db.get_alerts(limit=10000)
    summary = {"NEW": 0, "ACKNOWLEDGED": 0, "RESOLVED": 0, "total": len(all_alerts)}
    for a in all_alerts:
        s = a.get("status", "NEW")
        if s in summary:
            summary[s] += 1
    return summary
