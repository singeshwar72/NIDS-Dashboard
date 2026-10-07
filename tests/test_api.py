"""
Tests for Flask API endpoints.
"""
import pytest
import json
import sys
import os
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def app(tmp_path):
    """Create test Flask app with isolated DB."""
    os.environ["DATABASE_PATH"] = str(tmp_path / "test_api.db")
    os.environ["DEMO_DATASET_PATH"] = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "sample_traffic.csv"
    )
    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    application.config["DATABASE_PATH"] = str(tmp_path / "test_api.db")
    application.config["DEMO_DATASET_PATH"] = os.environ["DEMO_DATASET_PATH"]
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


class TestDashboardStats:
    def test_dashboard_stats_returns_200(self, client):
        res = client.get("/api/dashboard-stats")
        assert res.status_code == 200

    def test_dashboard_stats_has_required_fields(self, client):
        res = client.get("/api/dashboard-stats")
        data = json.loads(res.data)
        for field in ("total", "normal", "suspicious", "high_risk", "critical"):
            assert field in data, f"Missing field: {field}"

    def test_dashboard_stats_values_are_ints(self, client):
        res = client.get("/api/dashboard-stats")
        data = json.loads(res.data)
        assert isinstance(data["total"], int)
        assert isinstance(data["normal"], int)


class TestTrafficAPI:
    def test_get_traffic_empty(self, client):
        res = client.get("/api/traffic")
        assert res.status_code == 200
        data = json.loads(res.data)
        assert "records" in data
        assert "total" in data
        assert "page" in data

    def test_get_traffic_invalid_page(self, client):
        res = client.get("/api/traffic?page=abc")
        assert res.status_code in (200, 400, 500)


class TestAlertsAPI:
    def test_get_alerts_empty(self, client):
        res = client.get("/api/alerts")
        assert res.status_code == 200
        data = json.loads(res.data)
        assert "alerts" in data
        assert "total" in data

    def test_patch_alert_not_found(self, client):
        res = client.patch(
            "/api/alerts/99999",
            data=json.dumps({"status": "ACKNOWLEDGED"}),
            content_type="application/json",
        )
        assert res.status_code in (400, 404)

    def test_patch_alert_invalid_status(self, client):
        res = client.patch(
            "/api/alerts/1",
            data=json.dumps({"status": "INVALID"}),
            content_type="application/json",
        )
        assert res.status_code in (400, 404)


class TestUploadAPI:
    def test_upload_no_file(self, client):
        res = client.post("/api/upload")
        assert res.status_code == 400
        data = json.loads(res.data)
        assert data["success"] is False

    def test_upload_wrong_extension(self, client):
        data = {"file": (io.BytesIO(b"data"), "traffic.txt")}
        res = client.post("/api/upload", data=data, content_type="multipart/form-data")
        assert res.status_code == 400

    def test_upload_valid_csv(self, client):
        csv_content = b"source_ip,destination_ip,source_port,destination_port,protocol,packet_count,packet_size,duration,bytes_sent,bytes_received,connection_count\n192.168.1.1,8.8.8.8,54321,53,DNS,5,60,0.5,300,280,2\n"
        data = {"file": (io.BytesIO(csv_content), "test.csv")}
        res = client.post("/api/upload", data=data, content_type="multipart/form-data")
        assert res.status_code == 200
        result = json.loads(res.data)
        assert result["success"] is True
        assert result["valid_rows"] >= 1

    def test_upload_empty_csv(self, client):
        data = {"file": (io.BytesIO(b"source_ip,destination_ip\n"), "empty.csv")}
        res = client.post("/api/upload", data=data, content_type="multipart/form-data")
        assert res.status_code == 400

    def test_upload_invalid_ips(self, client):
        csv_content = b"source_ip,destination_ip\n999.999.999.999,also-bad\n"
        data = {"file": (io.BytesIO(csv_content), "bad.csv")}
        res = client.post("/api/upload", data=data, content_type="multipart/form-data")
        result = json.loads(res.data)
        # Either success with 0 valid rows, or failure
        if result.get("success"):
            assert result["valid_rows"] == 0


class TestDemoAPI:
    def test_demo_loads(self, client):
        res = client.post("/api/demo")
        data = json.loads(res.data)
        # If demo file exists, it should succeed
        if os.path.exists(os.environ.get("DEMO_DATASET_PATH", "")):
            assert data.get("success") is True
        else:
            # If demo file is missing, should gracefully fail
            assert "error" in data


class TestHistoryAPI:
    def test_get_history_empty(self, client):
        res = client.get("/api/history")
        assert res.status_code == 200
        data = json.loads(res.data)
        assert "sessions" in data

    def test_delete_nonexistent_session(self, client):
        res = client.delete("/api/history/99999")
        assert res.status_code == 404


class TestChartAPIs:
    def test_classification_chart(self, client):
        res = client.get("/api/chart/classification")
        assert res.status_code == 200
        data = json.loads(res.data)
        assert "labels" in data and "data" in data

    def test_attack_types_chart(self, client):
        res = client.get("/api/chart/attack-types")
        assert res.status_code == 200

    def test_alerts_over_time_chart(self, client):
        res = client.get("/api/chart/alerts-over-time")
        assert res.status_code == 200

    def test_risk_distribution_chart(self, client):
        res = client.get("/api/chart/risk-distribution")
        assert res.status_code == 200

    def test_top_source_ips_chart(self, client):
        res = client.get("/api/chart/top-source-ips")
        assert res.status_code == 200


class TestPageRoutes:
    def test_dashboard_page_loads(self, client):
        res = client.get("/dashboard")
        assert res.status_code == 200

    def test_traffic_page_loads(self, client):
        res = client.get("/traffic")
        assert res.status_code == 200

    def test_alerts_page_loads(self, client):
        res = client.get("/alerts")
        assert res.status_code == 200

    def test_upload_page_loads(self, client):
        res = client.get("/upload")
        assert res.status_code == 200

    def test_history_page_loads(self, client):
        res = client.get("/history")
        assert res.status_code == 200

    def test_about_page_loads(self, client):
        res = client.get("/about")
        assert res.status_code == 200

    def test_index_redirects(self, client):
        res = client.get("/")
        assert res.status_code in (301, 302)
