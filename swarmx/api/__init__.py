import json
import logging
import uuid
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from swarmx.audit import record_audit
from swarmx.database import connect
from swarmx.incident_manager import add_note, analyze_incident, update_incident
from swarmx.ingestion import DEMO_SCENARIOS, IngestionError, ingest_file, load_demo_scenario
from swarmx.reporting import build_incident_report, export_events_csv, render_report_html
from swarmx.services import alert_list, dashboard_data, event_list, incident_list, network_data
from swarmx.validators import pagination


LOGGER = logging.getLogger(__name__)
api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def _ok(data, status=200, meta=None):
    return jsonify({"success": True, "data": data, "error": None, "meta": meta or {}}), status


def _error(message, status=400):
    return jsonify({"success": False, "data": None, "error": {"message": message}, "meta": {}}), status


def _database():
    from flask import current_app
    return current_app.config["DATABASE"]


def _json_object():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise ValueError("Request body must be a JSON object.")
    return value


@api_v1.errorhandler(ValueError)
def invalid_input(error):
    return _error(str(error), 400)


@api_v1.get("/health")
def health():
    with connect(_database()) as db:
        db.execute("SELECT 1").fetchone()
    return _ok({"status": "ok", "application": "SwarmX", "analysis_mode": "local-deterministic"})


@api_v1.get("/dashboard/summary")
def dashboard_summary():
    return _ok(dashboard_data(_database()))


@api_v1.get("/dashboard/timeline")
def dashboard_timeline():
    return _ok(dashboard_data(_database())["activity"])


@api_v1.get("/dashboard/severity")
def dashboard_severity():
    return _ok(dashboard_data(_database())["severity"])


@api_v1.get("/dashboard/top-sources")
def dashboard_sources():
    return _ok(dashboard_data(_database())["top_sources"])


@api_v1.get("/events")
def events():
    result = event_list(_database(), request.args)
    return _ok(result["items"], meta={key: result[key] for key in ("page", "limit", "total")})


@api_v1.get("/events/types")
def event_types():
    with connect(_database()) as db:
        types = db.execute("SELECT DISTINCT event_type FROM events ORDER BY event_type").fetchall()
    return _ok([row["event_type"] for row in types])


@api_v1.get("/events/<int:event_id>")
def event_detail(event_id):
    with connect(_database()) as db:
        event = db.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if not event:
            return _error("Event not found.", 404)
        alerts = db.execute(
            """SELECT a.*,i.incident_uid FROM alerts a JOIN incidents i ON i.id=a.incident_id
               WHERE a.event_id=? OR EXISTS(SELECT 1 FROM json_each(a.event_ids) x WHERE CAST(x.value AS INTEGER)=?)
               ORDER BY a.id""", (event_id, event_id)
        ).fetchall()
    data = dict(event)
    data["alerts"] = [dict(row) for row in alerts]
    return _ok(data)


@api_v1.post("/events/upload")
def upload_events():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return _error("Choose a CSV, JSON, or JSON Lines file.")
    settings = _settings_values()
    try:
        result = ingest_file(_database(), uploaded.stream, uploaded.filename,
                             max_records=int(settings.get("max_events_per_import", current_app.config["MAX_EVENT_COUNT"])),
                             deduplicate=settings.get("deduplicate_events", "true") == "true")
    except IngestionError as exc:
        record_audit(_database(), "file_ingest_failed", secure_filename(uploaded.filename)[:255],
                     {"error": str(exc)[:200]})
        return _error(str(exc))
    record_audit(_database(), "file_ingested", uploaded.filename, {
        "accepted": result["accepted"], "rejected": result["rejected"],
        "duplicates": result["duplicates"],
    })
    return _ok(result, 201)


@api_v1.post("/events/<int:event_id>/analyze")
def analyze_event(event_id):
    with connect(_database()) as db:
        event = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if not event:
            return _error("Event not found.", 404)
        incident = db.execute(
            """SELECT DISTINCT i.id FROM incidents i JOIN alerts a ON a.incident_id=i.id
               WHERE a.event_id=? OR EXISTS(SELECT 1 FROM json_each(a.event_ids) x WHERE CAST(x.value AS INTEGER)=?)
               ORDER BY i.id LIMIT 1""", (event_id, event_id)
        ).fetchone()
    if not incident:
        return _error("No detection alert is linked to this event.", 404)
    return _ok(analyze_incident(_database(), incident["id"]))


@api_v1.get("/alerts")
def alerts():
    result = alert_list(_database(), request.args)
    return _ok(result["items"], meta={key: result[key] for key in ("page", "limit", "total")})


@api_v1.get("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    with connect(_database()) as db:
        row = db.execute(
            """SELECT a.*,e.timestamp,e.source_ip,e.dest_ip,e.event_type,e.username,e.raw_json,
               i.incident_uid,i.title AS incident_title FROM alerts a
               JOIN events e ON e.id=a.event_id JOIN incidents i ON i.id=a.incident_id WHERE a.id=?""",
            (alert_id,),
        ).fetchone()
    return _ok(dict(row)) if row else _error("Alert not found.", 404)


def _set_alert_status(alert_id, status):
    with connect(_database()) as db:
        row = db.execute("SELECT id,status FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            return _error("Alert not found.", 404)
        allowed = {"New": {"Acknowledged", "Investigating"},
                   "Acknowledged": {"Investigating", "Resolved"},
                   "Investigating": {"Acknowledged", "Resolved"},
                   "Resolved": {"Investigating"}}
        if status not in allowed.get(row["status"], set()):
            return _error(f"Alert status cannot change from {row['status']} to {status}.")
        db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
    record_audit(_database(), "alert_status_changed", str(alert_id), {"status": status})
    return _ok({"id": alert_id, "status": status})


@api_v1.post("/alerts/<int:alert_id>/acknowledge")
def acknowledge_alert(alert_id):
    return _set_alert_status(alert_id, "Acknowledged")


@api_v1.post("/alerts/<int:alert_id>/investigate")
def investigate_alert(alert_id):
    return _set_alert_status(alert_id, "Investigating")


@api_v1.get("/incidents")
def incidents():
    result = incident_list(_database(), request.args)
    return _ok(result["items"], meta={key: result[key] for key in ("page", "limit", "total")})


@api_v1.post("/incidents")
def create_incident():
    body = _json_object()
    title = body.get("title")
    summary = body.get("summary", "")
    severity = body.get("severity", "Low")
    source_ip = body.get("source_ip", "")
    if not isinstance(title, str) or not title.strip() or len(title) > 200:
        return _error("Incident title is required and must be under 200 characters.")
    if not isinstance(summary, str) or len(summary) > 2000:
        return _error("Incident summary must be text under 2000 characters.")
    if severity not in {"Low", "Medium", "High", "Critical"}:
        return _error("Severity must be Low, Medium, High, or Critical.")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    with connect(_database()) as db:
        cursor = db.execute(
            """INSERT INTO incidents(title,summary,severity,source_ip,first_observed,last_observed,
               severity_rationale) VALUES(?,?,?,?,?,?,?)""",
            (title.strip(), summary.strip(), severity, str(source_ip)[:100], now, now,
             "Manually created; no automated evidence scoring."),
        )
        incident_id = cursor.lastrowid
        incident_uid = f"SWX-{now[:4]}-{incident_id:06d}"
        db.execute("UPDATE incidents SET incident_uid=? WHERE id=?", (incident_uid, incident_id))
    record_audit(_database(), "incident_created", str(incident_id), {"title": title[:200]})
    return _ok({"id": incident_id, "incident_uid": incident_uid}, 201)


@api_v1.get("/incidents/<int:incident_id>")
def incident_detail(incident_id):
    with connect(_database()) as db:
        incident = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not incident:
            return _error("Incident not found.", 404)
        alerts = db.execute(
            """SELECT a.*,e.timestamp,e.source_ip,e.dest_ip,e.event_type,e.username,e.action
               FROM alerts a JOIN events e ON e.id=a.event_id WHERE a.incident_id=?
               ORDER BY e.timestamp,e.id LIMIT 1000""", (incident_id,)
        ).fetchall()
        notes = db.execute("SELECT * FROM notes WHERE incident_id=? ORDER BY created_at", (incident_id,)).fetchall()
        history = db.execute("SELECT * FROM incident_history WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
        jobs = db.execute("SELECT id,job_uid,status,summary,started_at,completed_at FROM analysis_jobs WHERE incident_id=? ORDER BY id DESC LIMIT 10", (incident_id,)).fetchall()
    return _ok({"incident": dict(incident), "alerts": [dict(x) for x in alerts],
                "notes": [dict(x) for x in notes], "history": [dict(x) for x in history],
                "analysis_jobs": [dict(x) for x in jobs]})


@api_v1.patch("/incidents/<int:incident_id>")
def patch_incident(incident_id):
    body = _json_object()
    try:
        updated = update_incident(_database(), incident_id, body)
    except ValueError as exc:
        return _error(str(exc))
    if updated is None:
        return _error("Incident not found.", 404)
    record_audit(_database(), "incident_updated", str(incident_id), {
        key: value for key, value in body.items() if key in {"severity", "status", "assigned_analyst"}
    })
    return _ok(updated)


@api_v1.post("/incidents/<int:incident_id>/notes")
def incident_notes(incident_id):
    body = _json_object()
    try:
        note = add_note(_database(), incident_id, body.get("text"), body.get("author", "Local analyst"))
    except ValueError as exc:
        return _error(str(exc))
    if note is None:
        return _error("Incident not found.", 404)
    record_audit(_database(), "incident_note_added", str(incident_id), {})
    return _ok(note, 201)


@api_v1.get("/incidents/<int:incident_id>/timeline")
def incident_timeline(incident_id):
    with connect(_database()) as db:
        if not db.execute("SELECT 1 FROM incidents WHERE id=?", (incident_id,)).fetchone():
            return _error("Incident not found.", 404)
        events = db.execute(
            """SELECT DISTINCT e.* FROM events e JOIN alerts a ON
               (a.event_id=e.id OR EXISTS(SELECT 1 FROM json_each(a.event_ids) x WHERE CAST(x.value AS INTEGER)=e.id))
               WHERE a.incident_id=? ORDER BY e.timestamp,e.id LIMIT 1000""", (incident_id,)
        ).fetchall()
        history = db.execute("SELECT * FROM incident_history WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
    return _ok({"events": [dict(x) for x in events], "history": [dict(x) for x in history]})


@api_v1.post("/incidents/<int:incident_id>/analyze")
def incident_analyze(incident_id):
    try:
        analysis = analyze_incident(_database(), incident_id)
    except ValueError as exc:
        return _error(str(exc))
    if analysis is None:
        return _error("Incident not found.", 404)
    return _ok(analysis)


@api_v1.post("/incidents/<int:incident_id>/resolve")
def resolve_incident(incident_id):
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return _error("Request body must be a JSON object.")
    rationale = body.get("resolution_summary", "")
    if not isinstance(rationale, str) or not rationale.strip():
        return _error("Provide a resolution summary before resolving the incident.")
    try:
        result = update_incident(_database(), incident_id, {
            "status": "Resolved", "resolution_summary": rationale,
        })
    except ValueError as exc:
        return _error(str(exc))
    if result is None:
        return _error("Incident not found.", 404)
    record_audit(_database(), "incident_resolved", str(incident_id), {})
    return _ok(result)


@api_v1.get("/agents")
def agents():
    latest = {}
    with connect(_database()) as db:
        rows = db.execute(
            """SELECT ar.agent_id,ar.status,ar.completed_at,ar.error,ar.result
               FROM agent_runs ar WHERE ar.id IN
               (SELECT MAX(id) FROM agent_runs GROUP BY agent_id)"""
        ).fetchall()
    for row in rows:
        latest[row["agent_id"]] = dict(row)
    catalog = [
        ("detection_agent", "Detection Agent", "Summarize stored explainable rule detections."),
        ("threat_intelligence_agent", "Threat Intelligence Agent", "Report local context and intelligence gaps."),
        ("incident_analysis_agent", "Incident Analysis Agent", "Correlate evidence and construct incident timeline."),
        ("evidence_validator", "Evidence Validation Agent", "Validate evidence references against stored records."),
        ("reporting_agent", "Reporting Agent", "Compile evidence-based reports and recommendations."),
        ("coordinator", "Coordinator Agent", "Coordinate specialist analysis jobs."),
    ]
    return _ok([{"agent_id": key, "name": name, "responsibility": description,
                 "state": latest.get(key, {}).get("status", "Idle"),
                 "latest_run": latest.get(key)} for key, name, description in catalog])


@api_v1.get("/agents/runs")
def agent_runs():
    page, limit, offset = pagination(request.args)
    with connect(_database()) as db:
        total = db.execute("SELECT COUNT(*) FROM analysis_jobs").fetchone()[0]
        rows = db.execute(
            """SELECT j.*,i.incident_uid FROM analysis_jobs j LEFT JOIN incidents i ON i.id=j.incident_id
               ORDER BY j.id DESC LIMIT ? OFFSET ?""", (limit, offset)
        ).fetchall()
    return _ok([dict(row) for row in rows], meta={"page": page, "limit": limit, "total": total})


@api_v1.get("/agents/runs/<string:run_id>")
def agent_run_detail(run_id):
    with connect(_database()) as db:
        job = db.execute("SELECT * FROM analysis_jobs WHERE job_uid=?", (run_id,)).fetchone()
        if not job:
            return _error("Analysis run not found.", 404)
        runs = db.execute("SELECT * FROM agent_runs WHERE job_id=? ORDER BY id", (job["id"],)).fetchall()
    return _ok({"job": dict(job), "agents": [dict(row) for row in runs]})


@api_v1.post("/agents/analyze")
def agents_analyze():
    body = _json_object()
    try:
        incident_id = int(body.get("incident_id"))
    except (TypeError, ValueError):
        return _error("incident_id must be a valid integer.")
    try:
        result = analyze_incident(_database(), incident_id)
    except ValueError as exc:
        return _error(str(exc))
    if result is None:
        return _error("Incident not found.", 404)
    return _ok(result, 201)


@api_v1.get("/network/graph")
def network_graph():
    try:
        graph = network_data(_database(), request.args.get("limit", 100), request.args)
    except ValueError as exc:
        return _error(str(exc))
    return _ok(graph)


@api_v1.get("/reports")
def reports():
    page, limit, offset = pagination(request.args)
    with connect(_database()) as db:
        total = db.execute("SELECT COUNT(*) FROM generated_reports").fetchone()[0]
        rows = db.execute(
            "SELECT id,report_uid,incident_id,created_at FROM generated_reports ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return _ok([dict(row) for row in rows], meta={"page": page, "limit": limit, "total": total})


@api_v1.post("/reports/generate")
def generate_report():
    body = _json_object()
    try:
        incident_id = int(body.get("incident_id"))
    except (TypeError, ValueError):
        return _error("incident_id must be a valid integer.")
    report = build_incident_report(_database(), incident_id)
    if report is None:
        return _error("Incident not found.", 404)
    with connect(_database()) as db:
        db.execute(
            "INSERT INTO generated_reports(report_uid,incident_id,report_json,created_at) VALUES(?,?,?,?)",
            (report["report_id"], incident_id, json.dumps(report, ensure_ascii=False), report["generated_at"]),
        )
    record_audit(_database(), "report_generated", report["report_id"], {"incident_id": incident_id})
    return _ok(report, 201)


@api_v1.get("/reports/<int:report_id>")
def report_detail(report_id):
    with connect(_database()) as db:
        row = db.execute("SELECT report_json FROM generated_reports WHERE id=?", (report_id,)).fetchone()
    return _ok(json.loads(row["report_json"])) if row else _error("Report not found.", 404)


@api_v1.get("/reports/<int:report_id>/download")
def report_download(report_id):
    fmt = request.args.get("format", "json").lower()
    with connect(_database()) as db:
        row = db.execute("SELECT report_uid,report_json FROM generated_reports WHERE id=?", (report_id,)).fetchone()
    if not row:
        return _error("Report not found.", 404)
    data = json.loads(row["report_json"])
    if fmt not in {"json", "html"}:
        return _error("Report format must be json or html.")
    content = json.dumps(data, indent=2, ensure_ascii=False) if fmt == "json" else render_report_html(data)
    mimetype = "application/json" if fmt == "json" else "text/html"
    return send_file(__import__("io").BytesIO(content.encode("utf-8")), as_attachment=True,
                     download_name=f"{row['report_uid']}.{fmt}", mimetype=mimetype)


@api_v1.get("/demo/scenarios")
def demo_scenarios():
    return _ok([{"id": key, **value, "synthetic": True} for key, value in DEMO_SCENARIOS.items()])


@api_v1.post("/demo/scenarios/<string:scenario_id>/run")
def run_demo(scenario_id):
    try:
        result = load_demo_scenario(_database(), scenario_id)
    except ValueError as exc:
        return _error(str(exc))
    analyses = []
    for incident_id in result["incident_ids"]:
        analysis = analyze_incident(_database(), incident_id)
        if analysis:
            analyses.append({"incident_id": incident_id, "job_id": analysis["job_id"],
                             "validation_status": analysis["validation_status"]})
    result["analysis_runs"] = analyses
    record_audit(_database(), "demo_loaded", scenario_id, {
        "accepted": result["accepted"], "alerts": result["alerts_created"], "synthetic": True,
    })
    return _ok(result, 201)


@api_v1.delete("/demo/scenarios")
def reset_demo():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict) or body.get("confirm") is not True:
        return _error("Set confirm=true to remove synthetic demonstration records.")
    with connect(_database()) as db:
        incident_ids = [row["id"] for row in db.execute(
            """SELECT DISTINCT i.id FROM incidents i JOIN alerts a ON a.incident_id=i.id
               JOIN events e ON e.id=a.event_id WHERE e.is_synthetic=1"""
        )]
        synthetic_ids = {row["id"] for row in db.execute("SELECT id FROM events WHERE is_synthetic=1")}
        alert_rows = db.execute("SELECT id,event_ids FROM alerts").fetchall()
        for alert in alert_rows:
            related = set(json.loads(alert["event_ids"] or "[]"))
            remaining = sorted(related - synthetic_ids)
            if related and not remaining and related.intersection(synthetic_ids):
                db.execute("DELETE FROM alerts WHERE id=?", (alert["id"],))
            elif related.intersection(synthetic_ids):
                db.execute("UPDATE alerts SET event_id=?,event_ids=? WHERE id=?",
                           (remaining[-1], json.dumps(remaining), alert["id"]))
        events_removed = db.execute("DELETE FROM events WHERE is_synthetic=1").rowcount
        for incident_id in incident_ids:
            if not db.execute("SELECT 1 FROM alerts WHERE incident_id=?", (incident_id,)).fetchone():
                db.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
    record_audit(_database(), "demo_reset", "synthetic", {"events_removed": events_removed})
    return _ok({"events_removed": events_removed, "incidents_removed": len(incident_ids)})


def _settings_values():
    with connect(_database()) as db:
        return {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM app_settings")}


@api_v1.get("/settings")
def get_settings():
    values = _settings_values()
    values.pop("retention_days", None)
    values["database"] = "Configured local SQLite database"
    with connect(_database()) as db:
        rules = db.execute("SELECT rule_id,name,description,severity,enabled FROM detection_rules ORDER BY rule_id").fetchall()
        event_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return _ok({"settings": values, "rules": [dict(row) for row in rules],
                "database_status": "initialized", "event_count": event_count})


@api_v1.patch("/settings")
def update_settings():
    body = _json_object()
    if "retention_days" in body:
        return _error("Automatic data retention is not implemented; records are kept until manually removed.")
    supported = {"max_events_per_import", "deduplicate_events", "dashboard_refresh_seconds"}
    if set(body) - (supported | {"detection_rules"}):
        return _error("Unsupported setting. Only documented local settings may be changed.")
    normalized = {}
    for key, value in body.items():
        if key == "max_events_per_import":
            try:
                value = int(value)
            except (TypeError, ValueError):
                return _error("Import record limit must be an integer.")
            if not 1 <= value <= 100000:
                return _error("Import record limit must be from 1 to 100000.")
        elif key == "dashboard_refresh_seconds":
            try:
                value = int(value)
            except (TypeError, ValueError):
                return _error("Refresh interval must be an integer.")
            if not 5 <= value <= 300:
                return _error("Refresh interval must be from 5 to 300 seconds.")
        else:
            if not isinstance(value, bool):
                return _error("deduplicate_events must be a boolean.")
            value = str(value).lower()
        normalized[key] = str(value)
    rules = body.get("detection_rules")
    if rules is not None:
        if not isinstance(rules, dict) or any(not isinstance(value, bool) for value in rules.values()):
            return _error("detection_rules must map rule identifiers to boolean values.")
        with connect(_database()) as db:
            known = {row["rule_id"] for row in db.execute("SELECT rule_id FROM detection_rules")}
            if set(rules) - known:
                return _error(f"Unknown detection rule: {sorted(set(rules) - known)[0]}.")
            for rule_id, enabled in rules.items():
                db.execute("UPDATE detection_rules SET enabled=? WHERE rule_id=?",
                           (int(enabled), rule_id))
        normalized["detection_rules"] = json.dumps(rules)
    with connect(_database()) as db:
        for key, value in normalized.items():
            db.execute(
                "INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
    record_audit(_database(), "settings_updated", "application", {
        key: value for key, value in normalized.items() if key != "detection_rules"
    })
    return get_settings()


@api_v1.get("/audit")
def audit_entries():
    page, limit, offset = pagination(request.args)
    with connect(_database()) as db:
        total = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
                          (limit, offset)).fetchall()
    return _ok([dict(row) for row in rows], meta={"page": page, "limit": limit, "total": total})


@api_v1.get("/export/events.csv")
def events_csv():
    try:
        data = export_events_csv(_database(), request.args)
    except ValueError as exc:
        return _error(str(exc))
    return send_file(data, as_attachment=True, download_name="swarmx-events.csv", mimetype="text/csv")
