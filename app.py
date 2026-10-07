"""
NIDS Security Operations Dashboard - Main Application
Flask entry point: registers all routes and starts the server.
"""

import logging
import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.utils import secure_filename

from config import get_config
from database.database import DatabaseManager
from services.traffic_service import load_demo_dataset, process_csv_file
from services.alert_service import get_alerts, update_alert_status
from ml.predict import load_model, is_ml_available, get_predictor

# ------------------------------------------------------------------ #
# App Factory
# ------------------------------------------------------------------ #

def create_app():
    app = Flask(__name__)
    cfg = get_config()
    app.config.from_object(cfg)

    # Ensure upload folder exists
    os.makedirs(app.config.get("UPLOAD_FOLDER", "uploads"), exist_ok=True)

    # Database
    db = DatabaseManager(app.config["DATABASE_PATH"])
    app.extensions["db"] = db

    # Load ML model (optional; fallback to rule-based if unavailable)
    load_model()

    # ---------------------------------------------------------------- #
    # Logging
    # ---------------------------------------------------------------- #
    logging.basicConfig(
        level=logging.DEBUG if app.config.get("DEBUG") else logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    # ---------------------------------------------------------------- #
    # Jinja2 Template Filters / Globals
    # ---------------------------------------------------------------- #

    def nids_class_color(cls: str) -> str:
        """Map classification label to CSS badge class."""
        _map = {
            "NORMAL": "badge-normal",
            "LOW RISK": "badge-low",
            "SUSPICIOUS": "badge-suspicious",
            "HIGH RISK": "badge-high",
            "CRITICAL": "badge-critical",
        }
        return _map.get(str(cls).upper(), "badge-normal")

    app.jinja_env.globals["NIDS_class_color"] = nids_class_color

    # ---------------------------------------------------------------- #
    # Security Headers
    # ---------------------------------------------------------------- #
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # ---------------------------------------------------------------- #
    # Error Handlers
    # ---------------------------------------------------------------- #
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Endpoint not found"}), 404
        return render_template("dashboard.html", error="Page not found"), 404

    @app.errorhandler(413)
    def file_too_large(e):
        return jsonify({"success": False, "error": "File too large. Maximum size is 10 MB."}), 413

    @app.errorhandler(500)
    def server_error(e):
        app.logger.error("Internal server error: %s", e)
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        return render_template("dashboard.html", error="Internal server error"), 500

    # ---------------------------------------------------------------- #
    # Page Routes
    # ---------------------------------------------------------------- #

    @app.route("/")
    def index():
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    def dashboard():
        stats = db.get_dashboard_stats()
        detection_mode = "Rule-Based + ML" if is_ml_available() else "Rule-Based"
        return render_template(
            "dashboard.html",
            stats=stats,
            detection_mode=detection_mode,
            last_updated=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

    @app.route("/traffic")
    def traffic():
        return render_template("traffic.html")

    @app.route("/alerts")
    def alerts():
        return render_template("alerts.html")

    @app.route("/analysis/<int:record_id>")
    def analysis(record_id):
        record = db.get_traffic_record(record_id)
        if not record:
            return render_template("dashboard.html", error=f"Record #{record_id} not found"), 404
        return render_template("analysis.html", record=record)

    @app.route("/upload")
    def upload():
        return render_template("upload.html")

    @app.route("/history")
    def history():
        return render_template("history.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    # ---------------------------------------------------------------- #
    # API: Dashboard Statistics
    # ---------------------------------------------------------------- #

    @app.route("/api/dashboard-stats")
    def api_dashboard_stats():
        try:
            stats = db.get_dashboard_stats()
            detection_mode = "Rule-Based + ML" if is_ml_available() else "Rule-Based"
            stats["detection_mode"] = detection_mode
            stats["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            return jsonify(stats)
        except Exception as e:
            app.logger.error("dashboard-stats error: %s", e)
            return jsonify({"error": "Failed to fetch statistics"}), 500

    @app.route("/api/chart/classification")
    def api_chart_classification():
        try:
            stats = db.get_dashboard_stats()
            return jsonify({
                "labels": ["Normal", "Suspicious", "High Risk", "Critical"],
                "data": [
                    stats.get("normal", 0),
                    stats.get("suspicious", 0),
                    stats.get("high_risk", 0),
                    stats.get("critical", 0),
                ],
            })
        except Exception as e:
            app.logger.error("chart classification error: %s", e)
            return jsonify({"error": str(e)}), 500

    @app.route("/api/chart/attack-types")
    def api_chart_attack_types():
        try:
            rows = db.get_attack_type_distribution()
            return jsonify({
                "labels": [r["attack_type"] for r in rows],
                "data": [r["count"] for r in rows],
            })
        except Exception as e:
            app.logger.error("chart attack-types error: %s", e)
            return jsonify({"error": str(e)}), 500

    @app.route("/api/chart/alerts-over-time")
    def api_chart_alerts_over_time():
        try:
            days = int(request.args.get("days", 7))
            rows = db.get_alerts_over_time(days)
            return jsonify({
                "labels": [r["day"] for r in rows],
                "data": [r["count"] for r in rows],
            })
        except Exception as e:
            app.logger.error("chart alerts-over-time error: %s", e)
            return jsonify({"error": str(e)}), 500

    @app.route("/api/chart/risk-distribution")
    def api_chart_risk_distribution():
        try:
            dist = db.get_risk_score_distribution()
            return jsonify({
                "labels": ["Normal (0-19)", "Low Risk (20-39)", "Suspicious (40-59)", "High Risk (60-79)", "Critical (80-100)"],
                "data": [
                    dist.get("normal", 0) or 0,
                    dist.get("low_risk", 0) or 0,
                    dist.get("suspicious", 0) or 0,
                    dist.get("high_risk", 0) or 0,
                    dist.get("critical", 0) or 0,
                ],
            })
        except Exception as e:
            app.logger.error("chart risk-distribution error: %s", e)
            return jsonify({"error": str(e)}), 500

    @app.route("/api/chart/top-source-ips")
    def api_chart_top_source_ips():
        try:
            limit = int(request.args.get("limit", 10))
            rows = db.get_top_source_ips(limit)
            return jsonify({
                "labels": [r["source_ip"] for r in rows],
                "data": [r["count"] for r in rows],
                "max_risk": [round(r.get("max_risk", 0) or 0, 1) for r in rows],
            })
        except Exception as e:
            app.logger.error("chart top-source-ips error: %s", e)
            return jsonify({"error": str(e)}), 500

    # ---------------------------------------------------------------- #
    # API: Traffic Records
    # ---------------------------------------------------------------- #

    @app.route("/api/traffic")
    def api_traffic():
        try:
            page = max(1, int(request.args.get("page", 1)))
            page_size = min(200, max(10, int(request.args.get("page_size", 50))))
            classification = request.args.get("classification")
            protocol = request.args.get("protocol")
            search = request.args.get("search", "").strip() or None
            session_id_str = request.args.get("session_id")
            session_id = int(session_id_str) if session_id_str else None

            offset = (page - 1) * page_size
            records = db.get_traffic_records(
                limit=page_size,
                offset=offset,
                classification=classification,
                protocol=protocol,
                search=search,
                session_id=session_id,
            )
            total = db.count_traffic_records(
                classification=classification,
                protocol=protocol,
                search=search,
                session_id=session_id,
            )
            return jsonify({
                "records": records,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": max(1, (total + page_size - 1) // page_size),
            })
        except Exception as e:
            app.logger.error("api_traffic error: %s", e)
            return jsonify({"error": "Failed to fetch traffic records"}), 500

    @app.route("/api/traffic/<int:record_id>")
    def api_traffic_detail(record_id):
        try:
            record = db.get_traffic_record(record_id)
            if not record:
                return jsonify({"error": "Record not found"}), 404
            return jsonify(record)
        except Exception as e:
            app.logger.error("api_traffic_detail error: %s", e)
            return jsonify({"error": "Failed to fetch record"}), 500

    # ---------------------------------------------------------------- #
    # API: Alerts
    # ---------------------------------------------------------------- #

    @app.route("/api/alerts")
    def api_alerts():
        try:
            page = max(1, int(request.args.get("page", 1)))
            page_size = min(200, max(10, int(request.args.get("page_size", 50))))
            status = request.args.get("status")
            severity = request.args.get("severity")
            search = request.args.get("search", "").strip() or None

            result = get_alerts(db, page=page, page_size=page_size, status=status, severity=severity, search=search)
            return jsonify(result)
        except Exception as e:
            app.logger.error("api_alerts error: %s", e)
            return jsonify({"error": "Failed to fetch alerts"}), 500

    @app.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
    def api_update_alert(alert_id):
        try:
            data = request.get_json(silent=True) or {}
            new_status = data.get("status", "")
            result = update_alert_status(db, alert_id, new_status)
            if not result["success"]:
                return jsonify(result), 400
            return jsonify(result)
        except Exception as e:
            app.logger.error("api_update_alert error: %s", e)
            return jsonify({"error": "Failed to update alert"}), 500

    # ---------------------------------------------------------------- #
    # API: Scan Sessions / History
    # ---------------------------------------------------------------- #

    @app.route("/api/history")
    def api_history():
        try:
            page = max(1, int(request.args.get("page", 1)))
            page_size = min(100, max(5, int(request.args.get("page_size", 20))))
            offset = (page - 1) * page_size
            sessions = db.get_sessions(limit=page_size, offset=offset)
            total = db.count_sessions()
            return jsonify({
                "sessions": sessions,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": max(1, (total + page_size - 1) // page_size),
            })
        except Exception as e:
            app.logger.error("api_history error: %s", e)
            return jsonify({"error": "Failed to fetch history"}), 500

    @app.route("/api/history/<int:session_id>", methods=["DELETE"])
    def api_delete_history(session_id):
        try:
            session = db.get_session(session_id)
            if not session:
                return jsonify({"error": "Session not found"}), 404
            db.delete_session(session_id)
            return jsonify({"success": True, "session_id": session_id})
        except Exception as e:
            app.logger.error("api_delete_history error: %s", e)
            return jsonify({"error": "Failed to delete session"}), 500

    # ---------------------------------------------------------------- #
    # API: Upload CSV
    # ---------------------------------------------------------------- #

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        try:
            if "file" not in request.files:
                return jsonify({"success": False, "error": "No file provided."}), 400

            file = request.files["file"]
            if not file or file.filename == "":
                return jsonify({"success": False, "error": "No file selected."}), 400

            filename = secure_filename(file.filename or "")
            if not filename.lower().endswith(".csv"):
                return jsonify({"success": False, "error": "Only CSV files are accepted."}), 400

            predictor = get_predictor()
            result = process_csv_file(file, filename, db, ml_predictor=predictor)
            status_code = 200 if result.get("success") else 400
            return jsonify(result), status_code
        except Exception as e:
            app.logger.error("api_upload error: %s", e)
            return jsonify({"success": False, "error": "Upload processing failed."}), 500

    # ---------------------------------------------------------------- #
    # API: Load Demo Dataset
    # ---------------------------------------------------------------- #

    @app.route("/api/demo", methods=["POST"])
    def api_demo():
        try:
            demo_path = app.config.get("DEMO_DATASET_PATH", os.path.join("data", "sample_traffic.csv"))
            predictor = get_predictor()
            result = load_demo_dataset(demo_path, db, ml_predictor=predictor)
            status_code = 200 if result.get("success") else 400
            return jsonify(result), status_code
        except Exception as e:
            app.logger.error("api_demo error: %s", e)
            return jsonify({"success": False, "error": "Failed to load demo dataset."}), 500

    # ---------------------------------------------------------------- #
    # API: Analyze a traffic record
    # ---------------------------------------------------------------- #

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        """Analyze a single record submitted as JSON."""
        try:
            from detection.validators import validate_row
            from detection.classifier import classify_record

            data = request.get_json(silent=True) or {}
            is_valid, reason, sanitized = validate_row(data)
            if not is_valid:
                return jsonify({"success": False, "error": reason}), 400

            predictor = get_predictor()
            result = classify_record(sanitized, ml_predictor=predictor)
            return jsonify({"success": True, "result": result})
        except Exception as e:
            app.logger.error("api_analyze error: %s", e)
            return jsonify({"success": False, "error": "Analysis failed."}), 500

    return app


# ------------------------------------------------------------------ #
# Entry Point
# ------------------------------------------------------------------ #

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=app.config.get("DEBUG", True))
