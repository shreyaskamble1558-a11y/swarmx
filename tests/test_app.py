import io
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db")})
    test_client = app.test_client()
    page = test_client.get("/")
    token = re.search(r'<meta name="csrf-token" content="([^"]+)"', page.get_data(as_text=True))
    assert token
    test_client.environ_base["HTTP_X_CSRF_TOKEN"] = token.group(1)
    return test_client


def test_state_changing_requests_require_csrf_and_same_origin(client):
    token = client.environ_base["HTTP_X_CSRF_TOKEN"]
    path = "/api/v1/demo/scenarios/brute_force/run"
    missing_token = client.post(path, headers={"X-CSRF-Token": ""})
    assert missing_token.status_code == 403
    cross_origin = client.post(path, headers={
        "X-CSRF-Token": token,
        "Origin": "https://attacker.example",
        "Sec-Fetch-Site": "cross-site",
    })
    assert cross_origin.status_code == 403
    accepted = client.post(path)
    assert accepted.status_code == 201
    invalid_host = client.get("/", base_url="http://attacker.example")
    assert invalid_host.status_code == 400


def test_dashboard_lists_filter_and_paginate_server_side(client):
    assert client.post("/api/v1/demo/scenarios/brute_force/run").status_code == 201
    event_types = client.get("/api/v1/events/types").json["data"]
    assert "authentication" in event_types
    events = client.get("/api/v1/events?q=failed_login&limit=2").json
    assert len(events["data"]) == 2
    assert events["meta"]["total"] >= 5
    alerts = client.get("/api/v1/alerts?status=New&limit=1").json
    assert len(alerts["data"]) == 1
    assert alerts["meta"]["total"] >= 2
    incidents = client.get("/api/v1/incidents?q=Repeated%20authentication&limit=1").json
    assert len(incidents["data"]) == 1
    assert incidents["meta"]["total"] == 1


def test_settings_do_not_advertise_unimplemented_retention(client):
    settings = client.get("/api/v1/settings").json["data"]["settings"]
    assert "retention_days" not in settings
    response = client.patch("/api/v1/settings", json={"retention_days": 30})
    assert response.status_code == 400
    assert "not implemented" in response.json["error"]["message"]


def test_health_and_empty_dashboard(client):
    assert client.get("/api/health").json["status"] == "ok"
    metrics = client.get("/api/dashboard").json["metrics"]
    assert metrics["events"] == 0
    assert metrics["events_processed"] == 0
    assert metrics["alerts"] == 0
    assert metrics["active_rules"] >= 8
    assert client.get("/api/v1/health").json["success"] is True


def test_csv_ingestion_detects_brute_force_and_exports(client):
    rows = ["timestamp,source_ip,dest_ip,event_type,username,action"]
    rows.extend(f"{(datetime.now(timezone.utc)-timedelta(minutes=5-minute)).isoformat()},"
                f"198.51.100.9,10.0.0.2,authentication,admin,failed_login"
                for minute in range(1, 6))
    response = client.post("/api/ingest", data={
        "file": (io.BytesIO("\n".join(rows).encode()), "events.csv")
    }, content_type="multipart/form-data")
    assert response.status_code == 201
    assert response.json["accepted"] == 5
    assert response.json["alerts_created"] == 2
    incidents = client.get("/api/incidents").json
    assert incidents[0]["severity"] == "High"
    assert incidents[0]["title"] == "Repeated authentication failures"
    assert incidents[0]["alert_count"] == 2
    assert client.get("/api/export/events.csv").status_code == 200
    duplicate = client.post("/api/ingest", data={
        "file": (io.BytesIO("\n".join(rows).encode()), "again.csv")
    }, content_type="multipart/form-data")
    assert duplicate.json["duplicates"] == 5
    assert duplicate.json["accepted"] == 0


def test_json_ingestion_analysis_and_incident_controls(client):
    payload = [{"timestamp": datetime.now(timezone.utc).isoformat(), "src_ip": "203.0.113.20",
                "dst_ip": "10.0.0.4", "type": "malware_indicator", "action": "quarantined"}]
    response = client.post("/api/ingest", data={
        "file": (io.BytesIO(json.dumps(payload).encode()), "events.json")
    }, content_type="multipart/form-data")
    assert response.status_code == 201
    incident_id = client.get("/api/incidents").json[0]["id"]
    analysis = client.post(f"/api/v1/incidents/{incident_id}/analyze").json["data"]
    assert analysis["human_review_required"] is True
    assert all(item["validated"] for item in analysis["agent_findings"])
    assert analysis["job_id"]
    assert client.post(f"/api/v1/incidents/{incident_id}/notes",
                       json={"text": "Reviewed for demonstration."}).status_code == 201
    assert client.patch(f"/api/v1/incidents/{incident_id}",
                        json={"status": "Investigating"}).json["data"]["status"] == "Investigating"
    assert client.get(f"/api/incidents/{incident_id}/report").status_code == 200
    report = client.post("/api/v1/reports/generate", json={"incident_id": incident_id})
    assert report.status_code == 201
    assert report.json["data"]["report_id"].startswith("SWX-REPORT-")


def test_invalid_rows_reported_and_bad_status_rejected(client):
    response = client.post("/api/ingest", data={
        "file": (io.BytesIO(b"timestamp,source_ip,event_type\n2026-10-24T10:00:00Z,,authentication\n2026-10-24T10:00:00Z,not-an-ip,port_scan\n2026-10-24T10:00:00Z,192.0.2.4,port_scan\n"),
                 "events.csv")
    }, content_type="multipart/form-data")
    assert response.status_code == 201
    assert response.json["accepted"] == 1
    assert response.json["rejected"] == 2
    incident_id = client.get("/api/incidents").json[0]["id"]
    assert client.patch(f"/api/v1/incidents/{incident_id}",
                        json={"status": "Execute"}).status_code == 400
    assert client.patch(f"/api/v1/incidents/{incident_id}",
                        json={"status": []}).status_code == 400
    assert client.post(f"/api/v1/incidents/{incident_id}/notes",
                       json={"text": 12}).status_code == 400


def test_demo_scenario_and_network_graph(client):
    response = client.post("/api/demo", json={"scenario": "port_scan"})
    assert response.status_code == 201
    graph = client.get("/api/network").json
    assert len(graph["nodes"]) == 2
    assert graph["links"][0]["event_type"] == "port_scan"


def test_unrelated_events_do_not_trigger_brute_force(client):
    payload = [
        {"timestamp": (datetime.now(timezone.utc)-timedelta(minutes=4-minute)).isoformat(), "source_ip": "192.0.2.40",
         "dest_ip": "10.0.0.7", "event_type": "port_scan", "action": "service_probe"}
        for minute in range(4)
    ]
    payload.append({"timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": "192.0.2.40",
                    "event_type": "authentication", "action": "failed_login"})
    response = client.post("/api/ingest", data={
        "file": (io.BytesIO(json.dumps(payload).encode()), "mixed-events.json")
    }, content_type="multipart/form-data")
    assert response.status_code == 201
    assert response.json["incidents_created"] == 1
    incident = client.get("/api/incidents").json[0]
    assert incident["alert_count"] >= 1
    detail = client.get(f"/api/incidents/{incident['id']}").json
    assert sum(alert["rule_id"] == "brute_force" for alert in detail["alerts"]) == 0


def test_versioned_api_deduplicates_validates_settings_and_exports_safe_csv(client):
    event = {"timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": "192.0.2.1",
             "event_type": "audit", "message": "=HYPERLINK(\"http://example.invalid\")"}
    for _ in range(2):
        response = client.post("/api/v1/events/upload", data={
            "file": (io.BytesIO(json.dumps([event]).encode()), "safe.json")
        }, content_type="multipart/form-data")
        assert response.json["success"] is True
    summary = client.get("/api/v1/dashboard/summary").json["data"]
    assert summary["metrics"]["events"] == 1
    exported = client.get("/api/v1/export/events.csv").data.decode("utf-8-sig")
    assert "'=HYPERLINK" in exported
    assert client.get("/api/v1/events?page=-1").status_code == 400
    assert client.post("/api/v1/demo/scenarios/unknown/run").status_code == 400


def test_synthetic_catalog_and_demo_reset_preserve_imported_data(client):
    scenarios = client.get("/api/v1/demo/scenarios").json["data"]
    assert len(scenarios) >= 5
    imported = {"timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": "192.0.2.99",
                "event_type": "audit", "action": "reviewed"}
    client.post("/api/v1/events/upload", data={
        "file": (io.BytesIO(json.dumps([imported]).encode()), "imported.json")
    }, content_type="multipart/form-data")
    demo = client.post("/api/v1/demo/scenarios/brute_force/run")
    assert demo.status_code == 201
    assert demo.json["data"]["analysis_runs"]
    reset = client.delete("/api/v1/demo/scenarios", json={"confirm": True})
    assert reset.status_code == 200
    events = client.get("/api/v1/events?limit=50").json["data"]
    assert len(events) == 1
    assert events[0]["source_ip"] == "192.0.2.99"
