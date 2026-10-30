import hashlib
import json
import logging
import re

from swarmx.severity import classify_severity


LOGGER = logging.getLogger(__name__)
WINDOW_MINUTES = 10
RULES = {
    "auth_failure": ("Authentication failure", "Low", "A single failed or denied authentication event."),
    "brute_force": ("Repeated authentication failures", "High",
                    "At least five failures from a source/account within ten minutes."),
    "password_guessing": ("Password guessing pattern", "High",
                          "At least five failures against three or more accounts from one source in ten minutes."),
    "success_after_failures": ("Successful login after repeated failures", "High",
                               "A successful login followed at least three failures for the same source/account in ten minutes."),
    "privilege_change": ("Privileged account activity", "High",
                         "The event explicitly records privilege elevation or a privileged account action."),
    "port_scan": ("Port or service scan observed", "Medium",
                  "The event explicitly identifies scanning or service probing."),
    "suspicious_port": ("Configured sensitive service activity", "Medium",
                        "The event targets a configured service port in a suspicious/denied context."),
    "denied_connections": ("Repeated denied connections", "Medium",
                           "At least five denied connections from a source to the same destination/service in ten minutes."),
    "high_volume": ("High-volume event anomaly", "Medium",
                    "At least one hundred records from a source were observed in five minutes."),
    "suspicious_egress": ("Suspicious outbound activity", "Medium",
                          "Event type or action indicates potentially suspicious outbound traffic."),
    "malware_indicator": ("Malware indicator observed", "Critical",
                          "Event explicitly identifies a malware-related indicator."),
    "suspicious_combination": ("Multi-stage suspicious activity", "High",
                               "Malware and suspicious egress indicators were observed for the same source within thirty minutes."),
}
FAILED_PATTERN = re.compile(r"fail|denied|invalid_password|authentication_error|login_failure", re.I)
SUCCESS_PATTERN = re.compile(r"success|successful|login_ok|authenticated", re.I)
SENSITIVE_PORTS = {23, 445, 3389}


def _text(event, *fields):
    return " ".join(str(event.get(field) or "") for field in fields).lower()


def _recent_event_ids(db, event, predicate, minutes=WINDOW_MINUTES, extra_sql="", extra_params=()):
    sql = f"""SELECT id FROM events WHERE source_ip = ?
              AND datetime(timestamp) BETWEEN datetime(?, '-{int(minutes)} minutes') AND datetime(?)
              {extra_sql} ORDER BY timestamp, id"""
    return [row["id"] for row in db.execute(
        sql, (event["source_ip"], event["timestamp"], event["timestamp"], *extra_params)
    ) if predicate(row["id"])]


def _matches(db, event_id, event):
    findings = []
    text = _text(event, "event_type", "action", "result", "message")
    authentication = bool(re.search(r"auth|login|password", text))
    failed = authentication and bool(FAILED_PATTERN.search(text))
    successful = authentication and bool(SUCCESS_PATTERN.search(text)) and not failed
    related_failures = []
    account_sql = "AND (username = ? OR ? = '')"
    account_params = (event["username"], event["username"])
    if failed:
        related_failures = [row["id"] for row in db.execute(
            """SELECT id FROM events WHERE source_ip = ?
               AND datetime(timestamp) BETWEEN datetime(?, '-10 minutes') AND datetime(?)
               AND (lower(event_type || ' ' || action || ' ' || result || ' ' || message)
                    LIKE '%fail%' OR lower(action || ' ' || result) LIKE '%denied%'
                    OR lower(action || ' ' || result) LIKE '%invalid_password%')
               AND (username = ? OR ? = '') ORDER BY timestamp, id""",
            (event["source_ip"], event["timestamp"], event["timestamp"], *account_params),
        )]
        if len(related_failures) >= 5:
            findings.append(("brute_force", related_failures, {"threshold": 5, "window_minutes": 10,
                                                                "source_ip": event["source_ip"],
                                                                "username": event["username"]}))
        else:
            findings.append(("auth_failure", [event_id], {"single_failure": True}))
        all_failures = db.execute(
            """SELECT id, username FROM events WHERE source_ip = ?
               AND datetime(timestamp) BETWEEN datetime(?, '-10 minutes') AND datetime(?)
               AND (lower(event_type || ' ' || action || ' ' || result || ' ' || message)
                    LIKE '%fail%' OR lower(action || ' ' || result) LIKE '%denied%')
               ORDER BY timestamp, id""",
            (event["source_ip"], event["timestamp"], event["timestamp"]),
        ).fetchall()
        accounts = {row["username"] for row in all_failures if row["username"]}
        if len(all_failures) >= 5 and len(accounts) >= 3:
            findings.append(("password_guessing", [row["id"] for row in all_failures],
                             {"failed_attempts": len(all_failures), "distinct_accounts": len(accounts),
                              "window_minutes": 10}))
    if successful:
        failures = db.execute(
            """SELECT id FROM events WHERE source_ip = ? AND username = ?
               AND datetime(timestamp) BETWEEN datetime(?, '-10 minutes') AND datetime(?)
               AND lower(event_type || ' ' || action || ' ' || result || ' ' || message)
                   LIKE '%fail%' ORDER BY timestamp, id""",
            (event["source_ip"], event["username"], event["timestamp"], event["timestamp"]),
        ).fetchall()
        if len(failures) >= 3:
            findings.append(("success_after_failures", [row["id"] for row in failures] + [event_id],
                             {"prior_failures": len(failures), "window_minutes": 10,
                              "inference": "suspicious context; compromise is not established"}))

    if re.search(r"malware|ransomware|trojan|virus|malicious_file", text):
        findings.append(("malware_indicator", [event_id], {"matched_terms": "malware-related event/action"}))
    if re.search(r"privilege|sudo|admin_grant|role_change|elevation", text):
        findings.append(("privilege_change", [event_id], {"matched_terms": "explicit privilege-related event/action"}))
    if re.search(r"port.?scan|network.?scan|service.?probe", text):
        findings.append(("port_scan", [event_id], {"matched_terms": "explicit scan/service-probe event/action"}))
    if re.search(r"outbound|egress|exfiltrat|beacon|command.?and.?control", text):
        findings.append(("suspicious_egress", [event_id], {"matched_terms": "outbound/egress event/action"}))

    try:
        dest_port = int(event.get("dest_port") or 0)
    except (TypeError, ValueError):
        dest_port = 0
    if dest_port in SENSITIVE_PORTS and re.search(r"denied|fail|blocked|probe|scan", text):
        findings.append(("suspicious_port", [event_id], {"destination_port": dest_port,
                                                           "configured_ports": sorted(SENSITIVE_PORTS)}))

    denied = bool(re.search(r"denied|reject|blocked|drop", text))
    if denied and event.get("dest_ip"):
        denied_rows = db.execute(
            """SELECT id FROM events WHERE source_ip = ? AND dest_ip = ?
               AND COALESCE(dest_port, 0) = COALESCE(?, 0)
               AND datetime(timestamp) BETWEEN datetime(?, '-10 minutes') AND datetime(?)
               AND lower(action || ' ' || result || ' ' || message) LIKE '%denied%'
               ORDER BY timestamp,id""",
            (event["source_ip"], event["dest_ip"], event.get("dest_port"),
             event["timestamp"], event["timestamp"]),
        ).fetchall()
        if len(denied_rows) >= 5:
            findings.append(("denied_connections", [row["id"] for row in denied_rows],
                             {"threshold": 5, "destination_ip": event["dest_ip"],
                              "destination_port": dest_port or None, "window_minutes": 10}))

    volume = db.execute(
        """SELECT COUNT(*) FROM events WHERE source_ip = ?
           AND datetime(timestamp) BETWEEN datetime(?, '-5 minutes') AND datetime(?)""",
        (event["source_ip"], event["timestamp"], event["timestamp"]),
    ).fetchone()[0]
    if volume >= 100:
        volume_ids = [row["id"] for row in db.execute(
            """SELECT id FROM events WHERE source_ip = ?
               AND datetime(timestamp) BETWEEN datetime(?, '-5 minutes') AND datetime(?)
               ORDER BY timestamp,id""",
            (event["source_ip"], event["timestamp"], event["timestamp"]),
        )]
        findings.append(("high_volume", volume_ids, {"event_count": volume, "threshold": 100,
                                                      "window_minutes": 5}))

    if re.search(r"malware|ransomware|trojan|virus", text) or re.search(
        r"outbound|egress|exfiltrat|beacon|command.?and.?control", text
    ):
        combination = db.execute(
            """SELECT id, lower(event_type || ' ' || action || ' ' || message) AS text
               FROM events WHERE source_ip = ?
               AND datetime(timestamp) BETWEEN datetime(?, '-30 minutes') AND datetime(?)
               ORDER BY timestamp,id""",
            (event["source_ip"], event["timestamp"], event["timestamp"]),
        ).fetchall()
        ids = [row["id"] for row in combination]
        has_malware = any(re.search(r"malware|ransomware|trojan|virus", row["text"]) for row in combination)
        has_egress = any(re.search(r"outbound|egress|exfiltrat|beacon|command.?and.?control", row["text"])
                         for row in combination)
        if has_malware and has_egress:
            findings.append(("suspicious_combination", ids, {"categories": ["malware", "suspicious_egress"],
                                                              "window_minutes": 30}))
    return findings


def detect_and_store(db, event_id, event):
    created = []
    enabled_rules = {row["rule_id"] for row in db.execute(
        "SELECT rule_id FROM detection_rules WHERE enabled=1"
    )}
    for rule_id, event_ids, conditions in _matches(db, event_id, event):
        if rule_id not in enabled_rules:
            continue
        title, rule_severity, description = RULES[rule_id]
        event_ids = sorted(set(event_ids))
        fingerprint = hashlib.sha256(
            f"{rule_id}:{','.join(map(str, event_ids))}".encode("utf-8")
        ).hexdigest()
        existing = db.execute("SELECT id FROM alerts WHERE fingerprint = ?", (fingerprint,)).fetchone()
        if existing:
            continue
        severity_result = classify_severity(rule_severity, len(event_ids), rule_id)
        severity = severity_result["severity"]
        evidence = {"event_ids": event_ids, "source_ip": event["source_ip"],
                    "event_type": event["event_type"], "action": event["action"]}
        incident = db.execute(
            """SELECT id, severity FROM incidents
               WHERE source_ip = ? AND status IN ('New','Open','Investigating','Contained')
                 AND datetime(created_at) >= datetime('now', '-1 day')
               ORDER BY created_at DESC LIMIT 1""", (event["source_ip"],)
        ).fetchone()
        incident_created = incident is None
        if incident:
            incident_id = incident["id"]
            severity_result = classify_severity(
                max((incident["severity"], severity), key=("Low", "Medium", "High", "Critical").index),
                len(event_ids), rule_id
            )
            severity = severity_result["severity"]
            db.execute(
                """UPDATE incidents SET severity = ?, title = ?, summary = ?, confidence = ?,
                   severity_rationale = ?, last_observed = MAX(COALESCE(last_observed, ?), ?),
                   updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?""",
                (severity, title, description, severity_result["confidence"],
                 severity_result["explanation"], event["timestamp"], event["timestamp"], incident_id),
            )
        else:
            cursor = db.execute(
                """INSERT INTO incidents(title,summary,severity,confidence,source_ip,first_observed,last_observed,severity_rationale)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (title, description, severity, severity_result["confidence"], event["source_ip"],
                 event["timestamp"], event["timestamp"], severity_result["explanation"]),
            )
            incident_id = cursor.lastrowid
            incident_uid = f"SWX-{event['timestamp'][:4]}-{incident_id:06d}"
            db.execute("UPDATE incidents SET incident_uid = ? WHERE id = ?", (incident_uid, incident_id))

        previous_alert = db.execute(
            """SELECT id,event_ids,evidence FROM alerts
               WHERE incident_id = ? AND rule_id = ?
                 AND datetime(created_at) >= datetime('now', '-10 minutes')
               ORDER BY id DESC LIMIT 1""",
            (incident_id, rule_id),
        ).fetchone()
        if previous_alert:
            prior_ids = set(json.loads(previous_alert["event_ids"] or "[]"))
            merged_ids = sorted(prior_ids.union(event_ids))
            db.execute(
                "UPDATE alerts SET event_ids = ?, evidence = ?, fingerprint = ? WHERE id = ?",
                (json.dumps(merged_ids), json.dumps({**evidence, "event_ids": merged_ids}),
                 fingerprint, previous_alert["id"]),
            )
            continue

        cursor = db.execute(
            """INSERT INTO alerts(incident_id,event_id,rule_id,title,description,severity,confidence,
               evidence,event_ids,matching_conditions,rationale,fingerprint)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (incident_id, event_ids[-1], rule_id, title, description, severity,
             severity_result["confidence"], json.dumps(evidence), json.dumps(event_ids),
             json.dumps(conditions), severity_result["explanation"], fingerprint),
        )
        for linked_event_id in event_ids:
            if linked_event_id == event_ids[-1]:
                continue
            db.execute(
                "INSERT OR IGNORE INTO incident_history(incident_id,field,old_value,new_value,rationale) VALUES(?,?,?,?,?)",
                (incident_id, "related_event", "", str(linked_event_id), f"Related by rule {rule_id}"),
            )
        created.append({"id": cursor.lastrowid, "incident_id": incident_id, "rule_id": rule_id,
                        "incident_created": incident_created, "event_ids": event_ids})
        LOGGER.info("Detection rule %s created alert %s for event %s", rule_id, cursor.lastrowid, event_id)
    return created
