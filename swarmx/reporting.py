import csv
import html
import io
import json
import uuid
from datetime import datetime, timezone

from swarmx.database import connect
from swarmx.validators import csv_safe


def export_events_csv(database, args=None):
    args = args or {}
    filters, values = [], []
    if args.get("incident_id"):
        filters.append("""e.id IN (SELECT a.event_id FROM alerts a WHERE a.incident_id = ?
            UNION SELECT CAST(x.value AS INTEGER) FROM alerts a, json_each(a.event_ids) x WHERE a.incident_id = ?)""")
        values.extend([args["incident_id"], args["incident_id"]])
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with connect(database) as db:
        rows = db.execute(
            f"""SELECT id,event_uid,timestamp,source_ip,dest_ip,source_port,dest_port,protocol,
                event_type,username,hostname,action,result,message,source_file,is_synthetic
                FROM events e {where} ORDER BY timestamp DESC LIMIT 10000""", values
        ).fetchall()
    output = io.StringIO()
    fields = list(rows[0].keys()) if rows else [
        "id", "event_uid", "timestamp", "source_ip", "dest_ip", "source_port", "dest_port",
        "protocol", "event_type", "username", "hostname", "action", "result", "message",
        "source_file", "is_synthetic",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_safe(value) if key not in {"id", "source_port", "dest_port", "is_synthetic"} else value
                         for key, value in dict(row).items()})
    return io.BytesIO(output.getvalue().encode("utf-8-sig"))


def build_incident_report(database, incident_id):
    with connect(database) as db:
        incident = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not incident:
            return None
        alerts = db.execute(
            """SELECT a.*,e.timestamp,e.source_ip,e.dest_ip,e.event_type,e.username,e.action,e.message
               FROM alerts a JOIN events e ON e.id=a.event_id
               WHERE a.incident_id=? ORDER BY e.timestamp,e.id LIMIT 1000""", (incident_id,)
        ).fetchall()
        notes = db.execute("SELECT * FROM notes WHERE incident_id=? ORDER BY created_at", (incident_id,)).fetchall()
        history = db.execute("SELECT * FROM incident_history WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
        jobs = db.execute(
            "SELECT result,status,completed_at FROM analysis_jobs WHERE incident_id=? ORDER BY id DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
    analysis = json.loads(jobs["result"]) if jobs and jobs["result"] else {}
    return {
        "report_id": f"SWX-REPORT-{uuid.uuid4().hex[:12].upper()}",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "incident": dict(incident),
        "timeline": [dict(alert) for alert in alerts],
        "alerts": [dict(alert) for alert in alerts],
        "detection_rules": sorted({alert["rule_id"] for alert in alerts}),
        "agent_analysis": analysis,
        "agent_validation_status": analysis.get("validation_status", "Needs Review"),
        "analyst_notes": [dict(note) for note in notes],
        "status_history": [dict(item) for item in history],
        "severity_rationale": incident["severity_rationale"],
        "recommended_next_steps": analysis.get("recommended_next_steps", [
            "Review the source records and validate context using authoritative system logs.",
            "Record any response decision for human review.",
        ]),
        "limitations": analysis.get("limitations", [
            "Rule matches are indicators for triage, not proof of malicious activity.",
            "Business impact and asset criticality were not assessed.",
        ]),
        "human_review_required": True,
    }


def export_incident_report(database, incident_id):
    report = build_incident_report(database, incident_id)
    if report is None:
        return None
    return io.BytesIO(json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"))


def render_report_html(report):
    incident = report["incident"]
    items = "".join(
        f"<li><strong>{html.escape(str(item.get('timestamp', '')))}</strong> — "
        f"{html.escape(str(item.get('title', '')))}; {html.escape(str(item.get('description', '')))}</li>"
        for item in report["timeline"]
    )
    notes = "".join(f"<li>{html.escape(str(note['text']))}</li>" for note in report["analyst_notes"])
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>SwarmX {html.escape(incident['incident_uid'] or str(incident['id']))}</title>
    <style>body{{font:15px system-ui;max-width:900px;margin:40px auto;color:#182333}}h1,h2{{color:#17334b}}.meta{{color:#526477}}li{{margin:8px 0}}@media print{{button{{display:none}}}}</style>
    <button onclick="window.print()">Print / Save as PDF</button>
    <h1>SwarmX Incident Report</h1><p class="meta">{html.escape(report['report_id'])} · Generated {html.escape(report['generated_at'])}</p>
    <h2>{html.escape(incident['title'])}</h2><p>{html.escape(incident['summary'])}</p>
    <p>Severity: {html.escape(incident['severity'])} · Status: {html.escape(incident['status'])} · Source: {html.escape(incident['source_ip'])}</p>
    <p>Severity rationale: {html.escape(report['severity_rationale'])}</p>
    <h2>Observed event and alert timeline</h2><ol>{items or '<li>No linked records.</li>'}</ol>
    <h2>Detection rules</h2><p>{html.escape(', '.join(report['detection_rules']) or 'None')}</p>
    <h2>Analyst notes</h2><ul>{notes or '<li>No notes recorded.</li>'}</ul>
    <h2>Limitations</h2><ul>{''.join(f'<li>{html.escape(str(value))}</li>' for value in report['limitations'])}</ul>
    <p><strong>Human review required. No response actions were executed.</strong></p></html>"""
