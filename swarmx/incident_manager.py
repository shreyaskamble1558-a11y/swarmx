import json
from datetime import datetime, timezone

from swarmx.agents.coordinator import coordinate
from swarmx.audit import record_audit
from swarmx.database import connect


STATUS_TRANSITIONS = {
    "New": {"Open", "Investigating", "Closed"},
    "Open": {"Investigating", "Contained", "Resolved", "Closed"},
    "Investigating": {"Open", "Contained", "Resolved", "Closed"},
    "Contained": {"Investigating", "Resolved", "Closed"},
    "Resolved": {"Investigating", "Closed"},
    "Closed": {"Investigating"},
}
SEVERITIES = {"Low", "Medium", "High", "Critical"}


def update_incident(database, incident_id, payload):
    if not isinstance(payload, dict) or not payload:
        raise ValueError("Provide at least one incident field to update.")
    allowed = {"severity", "status", "assigned_analyst", "resolution_summary"}
    if set(payload) - (allowed | {"rationale"}):
        raise ValueError("Only severity, status, assigned analyst, and resolution summary may be updated.")
    if not set(payload).intersection(allowed):
        raise ValueError("Provide at least one incident field to update.")
    if "severity" in payload and (
        not isinstance(payload["severity"], str) or payload["severity"] not in SEVERITIES
    ):
        raise ValueError("Severity must be Low, Medium, High, or Critical.")
    if "status" in payload and (
        not isinstance(payload["status"], str) or payload["status"] not in STATUS_TRANSITIONS
    ):
        raise ValueError("Status must be New, Open, Investigating, Contained, Resolved, or Closed.")
    for field in ("assigned_analyst", "resolution_summary"):
        if field in payload and (not isinstance(payload[field], str) or len(payload[field]) > 2000):
            raise ValueError(f"{field.replace('_', ' ').capitalize()} must be text under 2000 characters.")
    rationale = payload.get("rationale", "")
    if "rationale" in payload and (not isinstance(rationale, str) or len(rationale.strip()) < 5):
        raise ValueError("Provide a severity change rationale of at least 5 characters.")
    with connect(database) as db:
        current = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if current is None:
            return None
        if "severity" in payload and payload["severity"] != current["severity"] and not rationale.strip():
            raise ValueError("A rationale is required when changing incident severity.")
        if "status" in payload and payload["status"] != current["status"]:
            if payload["status"] not in STATUS_TRANSITIONS[current["status"]]:
                raise ValueError(f"Status cannot change from {current['status']} to {payload['status']}.")
        fields = {key: value.strip() if isinstance(value, str) else value
                  for key, value in payload.items() if key in allowed}
        for field, value in fields.items():
            old_value = current[field] or ""
            if str(old_value) == str(value):
                continue
            db.execute(
                """INSERT INTO incident_history(incident_id,field,old_value,new_value,rationale)
                   VALUES(?,?,?,?,?)""",
                (incident_id, field, str(old_value), str(value),
                 rationale.strip() if field == "severity" else ""),
            )
        if fields:
            assignments = ", ".join(f"{key} = ?" for key in fields)
            db.execute(
                f"""UPDATE incidents SET {assignments},
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?""",
                (*fields.values(), incident_id),
            )
        return dict(db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())


def add_note(database, incident_id, text, author="Local analyst"):
    if not isinstance(text, str):
        raise ValueError("Note must be text containing 1 to 2000 characters.")
    note = text.strip()
    if not note or len(note) > 2000:
        raise ValueError("Note must contain 1 to 2000 characters.")
    if not isinstance(author, str) or len(author) > 100:
        raise ValueError("Note author must be text under 100 characters.")
    with connect(database) as db:
        if not db.execute("SELECT 1 FROM incidents WHERE id = ?", (incident_id,)).fetchone():
            return None
        cursor = db.execute(
            "INSERT INTO notes(incident_id,author,text) VALUES(?,?,?)",
            (incident_id, author, note),
        )
        db.execute("UPDATE incidents SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
                   (incident_id,))
        return dict(db.execute("SELECT * FROM notes WHERE id = ?", (cursor.lastrowid,)).fetchone())


def analyze_incident(database, incident_id):
    with connect(database) as db:
        incident = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not incident:
            return None
        alerts = db.execute(
            """SELECT a.*, e.timestamp, e.source_ip, e.dest_ip, e.event_type, e.username,
               e.hostname, e.action, e.result, e.message
               FROM alerts a JOIN events e ON e.id = a.event_id
               WHERE a.incident_id = ? ORDER BY e.timestamp, e.id LIMIT 1000""",
            (incident_id,),
        ).fetchall()
        events = db.execute(
            """SELECT DISTINCT e.* FROM events e
               LEFT JOIN alerts a ON a.event_id = e.id
               WHERE a.incident_id = ? ORDER BY e.timestamp,e.id LIMIT 1000""",
            (incident_id,),
        ).fetchall()
        job_uid = f"SWX-ANALYSIS-{incident_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        cursor = db.execute(
            "INSERT INTO analysis_jobs(job_uid,incident_id,status,started_at) VALUES(?,?,?,?)",
            (job_uid, incident_id, "Running", started),
        )
        job_id = cursor.lastrowid

    try:
        analysis = coordinate(dict(incident), [dict(alert) for alert in alerts],
                              [dict(event) for event in events], job_uid)
        status = "Completed" if all(run["status"] == "Completed" for run in analysis["agent_runs"]) else "Needs Review"
        for run in analysis["agent_runs"]:
            with connect(database) as db:
                db.execute(
                    """INSERT INTO agent_runs(job_id,agent_id,status,result,error,started_at,completed_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (job_id, run["agent_id"], run["status"], json.dumps(run["result"]),
                     run.get("error", ""), run["started_at"], run["completed_at"]),
                )
        completed = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        with connect(database) as db:
            db.execute(
                """UPDATE analysis_jobs SET status = ?, summary = ?, result = ?, completed_at = ?
                   WHERE id = ?""",
                (status, analysis["assessment"], json.dumps(analysis), completed, job_id),
            )
        record_audit(database, "agent_analysis_completed", str(incident_id),
                     {"job_id": job_uid, "status": status, "agents": len(analysis["agent_findings"])})
        analysis["job_id"] = job_uid
        analysis["job_status"] = status
        return analysis
    except Exception as exc:
        completed = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        with connect(database) as db:
            db.execute(
                "UPDATE analysis_jobs SET status='Failed', error=?, completed_at=? WHERE id=?",
                (str(exc)[:500], completed, job_id),
            )
        raise
