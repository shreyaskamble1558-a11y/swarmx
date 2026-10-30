import json

from swarmx.database import connect
from swarmx.validators import iso_timestamp, pagination


def dashboard_data(database):
    with connect(database) as db:
        event_total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alert_total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_incidents = db.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('New','Open','Investigating','Contained')"
        ).fetchone()[0]
        critical = db.execute(
            """SELECT COUNT(*) FROM incidents WHERE severity = 'Critical'
               AND status IN ('New','Open','Investigating','Contained')"""
        ).fetchone()[0]
        severity = db.execute(
            "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity"
        ).fetchall()
        activity = db.execute(
            """SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS count FROM events
               WHERE datetime(timestamp) >= datetime('now', '-6 days') GROUP BY day ORDER BY day"""
        ).fetchall()
        recent = db.execute(
            """SELECT i.*, COUNT(a.id) AS alert_count FROM incidents i
               LEFT JOIN alerts a ON a.incident_id = i.id
               GROUP BY i.id ORDER BY i.updated_at DESC LIMIT 6"""
        ).fetchall()
        events_processed = event_total
        investigating = db.execute("SELECT COUNT(*) FROM incidents WHERE status='Investigating'").fetchone()[0]
        resolved = db.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('Resolved','Closed')"
        ).fetchone()[0]
        rules = db.execute("SELECT COUNT(*) FROM detection_rules WHERE enabled=1").fetchone()[0]
        completed_jobs = db.execute(
            "SELECT COUNT(*) FROM analysis_jobs WHERE status IN ('Completed','Needs Review')"
        ).fetchone()[0]
        failures = db.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='file_ingest_failed'"
        ).fetchone()[0]
        status_distribution = db.execute(
            "SELECT status,COUNT(*) AS count FROM incidents GROUP BY status"
        ).fetchall()
        top_sources = db.execute(
            "SELECT source_ip,COUNT(*) AS count FROM events GROUP BY source_ip ORDER BY count DESC LIMIT 5"
        ).fetchall()
        top_rules = db.execute(
            "SELECT rule_id,COUNT(*) AS count FROM alerts GROUP BY rule_id ORDER BY count DESC LIMIT 5"
        ).fetchall()
        recent_alerts = db.execute(
            """SELECT a.id,a.title,a.rule_id,a.severity,a.status,a.created_at,i.incident_uid
               FROM alerts a JOIN incidents i ON i.id=a.incident_id ORDER BY a.id DESC LIMIT 5"""
        ).fetchall()
        actions = db.execute(
            "SELECT action,target,created_at FROM audit_log ORDER BY id DESC LIMIT 5"
        ).fetchall()
        agent_status = db.execute(
            """SELECT agent_id,status,completed_at,error FROM agent_runs
               WHERE id IN (SELECT MAX(id) FROM agent_runs GROUP BY agent_id) ORDER BY agent_id"""
        ).fetchall()
    return {
        "metrics": {
            "events": event_total, "events_processed": events_processed, "alerts": alert_total,
            "open_incidents": open_incidents, "critical_incidents": critical,
            "investigating_incidents": investigating, "resolved_incidents": resolved,
            "active_rules": rules, "analysis_jobs_completed": completed_jobs,
            "ingestion_failures": failures,
        },
        "severity": [dict(row) for row in severity],
        "status_distribution": [dict(row) for row in status_distribution],
        "activity": [dict(row) for row in activity],
        "top_sources": [dict(row) for row in top_sources],
        "top_rules": [dict(row) for row in top_rules],
        "recent_alerts": [dict(row) for row in recent_alerts],
        "recent_actions": [dict(row) for row in actions],
        "agent_status": [dict(row) for row in agent_status],
        "recent_incidents": [dict(row) for row in recent],
    }


def incident_list(database, args=None):
    args = args or {}
    page, limit, offset = pagination(args, default_limit=50)
    filters = []
    values = []
    if args.get("status"):
        if args["status"] not in {"New", "Open", "Investigating", "Contained", "Resolved", "Closed"}:
            raise ValueError("Invalid incident status filter.")
        filters.append("i.status = ?")
        values.append(args["status"])
    if args.get("severity"):
        if args["severity"] not in {"Low", "Medium", "High", "Critical"}:
            raise ValueError("Invalid severity filter.")
        filters.append("i.severity = ?")
        values.append(args["severity"])
    if args.get("q"):
        query = f"%{args['q'][:100]}%"
        filters.append("(i.title LIKE ? OR i.source_ip LIKE ? OR i.summary LIKE ?)")
        values.extend([query] * 3)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with connect(database) as db:
        total = db.execute(f"SELECT COUNT(*) FROM incidents i {where}", values).fetchone()[0]
        rows = db.execute(
            f"""SELECT i.*, COUNT(a.id) AS alert_count, MAX(a.created_at) AS last_alert
                FROM incidents i LEFT JOIN alerts a ON a.incident_id=i.id {where}
                GROUP BY i.id ORDER BY i.updated_at DESC LIMIT ? OFFSET ?""",
            (*values, limit, offset),
        ).fetchall()
    return {"items": [dict(row) for row in rows], "page": page, "limit": limit, "total": total}


def event_list(database, args=None):
    args = args or {}
    page, limit, offset = pagination(args, default_limit=50)
    filters = []
    values = []
    if args.get("event_type"):
        filters.append("e.event_type = ?")
        values.append(args["event_type"][:100])
    if args.get("source_ip"):
        filters.append("e.source_ip = ?")
        values.append(args["source_ip"][:100])
    if args.get("q"):
        filters.append(
            "(e.event_type LIKE ? OR e.source_ip LIKE ? OR e.dest_ip LIKE ? OR "
            "e.username LIKE ? OR e.action LIKE ? OR e.message LIKE ?)"
        )
        values.extend([f"%{args['q'][:100]}%"] * 6)
    if args.get("start"):
        filters.append("datetime(e.timestamp) >= datetime(?)")
        values.append(iso_timestamp(args["start"], "start"))
    if args.get("end"):
        filters.append("datetime(e.timestamp) <= datetime(?)")
        values.append(iso_timestamp(args["end"], "end"))
    if args.get("severity"):
        if args["severity"] not in {"Low", "Medium", "High", "Critical"}:
            raise ValueError("Invalid severity filter.")
        filters.append("""EXISTS(SELECT 1 FROM alerts a WHERE
            (a.event_id=e.id OR EXISTS(SELECT 1 FROM json_each(a.event_ids) x WHERE CAST(x.value AS INTEGER)=e.id))
            AND a.severity=?)""")
        values.append(args["severity"])
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with connect(database) as db:
        total = db.execute(f"SELECT COUNT(*) FROM events e {where}", values).fetchone()[0]
        rows = db.execute(
            f"""SELECT e.*, (SELECT COUNT(*) FROM alerts a WHERE a.event_id=e.id OR
                EXISTS(SELECT 1 FROM json_each(a.event_ids) x WHERE CAST(x.value AS INTEGER)=e.id)) AS alert_count,
                (SELECT GROUP_CONCAT(DISTINCT a.severity) FROM alerts a WHERE a.event_id=e.id OR
                EXISTS(SELECT 1 FROM json_each(a.event_ids) x WHERE CAST(x.value AS INTEGER)=e.id)) AS alert_severities
                FROM events e {where} ORDER BY e.timestamp DESC,e.id DESC LIMIT ? OFFSET ?""",
            (*values, limit, offset),
        ).fetchall()
    return {"items": [dict(row) for row in rows], "page": page, "limit": limit, "total": total}


def alert_list(database, args=None):
    args = args or {}
    page, limit, offset = pagination(args, default_limit=50)
    filters = []
    values = []
    for key, column in (("severity", "a.severity"), ("status", "a.status"), ("rule_id", "a.rule_id")):
        if args.get(key):
            if key == "severity" and args[key] not in {"Low", "Medium", "High", "Critical"}:
                raise ValueError("Invalid severity filter.")
            if key == "status" and args[key] not in {"New", "Acknowledged", "Investigating", "Resolved"}:
                raise ValueError("Invalid alert status filter.")
            filters.append(f"{column} = ?")
            values.append(args[key])
    if args.get("q"):
        filters.append("(a.title LIKE ? OR a.description LIKE ? OR e.source_ip LIKE ?)")
        values.extend([f"%{args['q'][:100]}%"] * 3)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with connect(database) as db:
        total = db.execute(
            f"SELECT COUNT(*) FROM alerts a JOIN events e ON e.id=a.event_id {where}", values
        ).fetchone()[0]
        rows = db.execute(
            f"""SELECT a.*,e.timestamp,e.source_ip,e.dest_ip,e.event_type,e.username,
                i.incident_uid FROM alerts a JOIN events e ON e.id=a.event_id
                JOIN incidents i ON i.id=a.incident_id {where}
                ORDER BY a.id DESC LIMIT ? OFFSET ?""", (*values, limit, offset)
        ).fetchall()
    return {"items": [dict(row) for row in rows], "page": page, "limit": limit, "total": total}


def network_data(database, limit=100, filters=None):
    try:
        limit = min(max(int(limit), 1), 500)
    except (TypeError, ValueError) as exc:
        raise ValueError("Network graph limit must be an integer.") from exc
    filters = filters or {}
    if filters.get("severity") and filters["severity"] not in {"Low", "Medium", "High", "Critical"}:
        raise ValueError("Invalid severity filter.")
    clauses = ["e.dest_ip != ''"]
    params = []
    if filters.get("severity"):
        clauses.append("""EXISTS(SELECT 1 FROM alerts a WHERE a.severity=? AND
            (a.event_id=e.id OR EXISTS(SELECT 1 FROM json_each(a.event_ids) x WHERE CAST(x.value AS INTEGER)=e.id)))""")
        params.append(filters["severity"])
    if filters.get("incident_id"):
        try:
            incident_id = int(filters["incident_id"])
        except (TypeError, ValueError) as exc:
            raise ValueError("incident_id must be a valid integer.") from exc
        clauses.append("""EXISTS(SELECT 1 FROM alerts a WHERE a.incident_id=? AND
            (a.event_id=e.id OR EXISTS(SELECT 1 FROM json_each(a.event_ids) x WHERE CAST(x.value AS INTEGER)=e.id)))""")
        params.append(incident_id)
    for key, op in (("start", ">="), ("end", "<=")):
        if filters.get(key):
            clauses.append(f"datetime(e.timestamp) {op} datetime(?)")
            params.append(iso_timestamp(filters[key], key))
    with connect(database) as db:
        rows = db.execute(
            f"""SELECT e.source_ip,e.dest_ip,e.event_type,COUNT(*) AS count,MAX(e.timestamp) AS last_seen
               FROM events e WHERE {' AND '.join(clauses)}
               GROUP BY e.source_ip,e.dest_ip,e.event_type ORDER BY count DESC LIMIT ?""",
            (*params, limit)
        ).fetchall()
    nodes, links = {}, []
    for row in rows:
        for ip, kind in ((row["source_ip"], "source"), (row["dest_ip"], "destination")):
            nodes.setdefault(ip, {"id": ip, "kind": kind, "events": 0})
            nodes[ip]["events"] += row["count"]
        links.append({"source": row["source_ip"], "target": row["dest_ip"],
                      "event_type": row["event_type"], "count": row["count"],
                      "last_seen": row["last_seen"]})
    return {"nodes": list(nodes.values()), "links": links}
