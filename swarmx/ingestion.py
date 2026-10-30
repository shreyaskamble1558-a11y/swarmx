import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone

from werkzeug.utils import secure_filename

from swarmx.database import connect
from swarmx.detection_engine import detect_and_store
from swarmx.normalization import normalize_event


LOGGER = logging.getLogger(__name__)
MAX_RECORDS_PER_IMPORT = 10000


class IngestionError(ValueError):
    pass


def _read_records(stream, filename, max_records=MAX_RECORDS_PER_IMPORT):
    safe_name = secure_filename(filename or "")
    suffix = safe_name.lower().rsplit(".", 1)[-1] if "." in safe_name else ""
    if suffix not in {"csv", "json", "jsonl", "ndjson"}:
        raise IngestionError("Only CSV, JSON, and JSON Lines files are supported.")
    try:
        content = stream.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8-sig")
        if not isinstance(content, str) or not content.strip():
            raise IngestionError("The uploaded file is empty.")
        if suffix == "csv":
            reader = csv.DictReader(io.StringIO(content))
            if not reader.fieldnames or not any(name.strip() for name in reader.fieldnames if name):
                raise IngestionError("CSV file must include a header row.")
            records = list(reader)
        elif suffix in {"jsonl", "ndjson"}:
            records = []
            for line_number, line in enumerate(content.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise IngestionError(f"Invalid JSON Lines record on line {line_number}: {exc.msg}.") from exc
        else:
            value = json.loads(content)
            if isinstance(value, dict):
                value = value.get("events", value.get("logs", [value]))
            if not isinstance(value, list):
                raise IngestionError("JSON must contain an event object or an array of events.")
            records = value
        if len(records) > max_records:
            raise IngestionError(f"File contains more than the {max_records:,} event limit.")
        return records
    except (UnicodeDecodeError, json.JSONDecodeError, csv.Error) as exc:
        raise IngestionError(f"Could not parse the uploaded {suffix.upper()} file.") from exc


def ingest_file(database, stream, filename, max_records=MAX_RECORDS_PER_IMPORT,
                deduplicate=True, synthetic=False):
    safe_name = secure_filename(filename or "")
    if not safe_name:
        raise IngestionError("The uploaded file must have a safe filename with a supported extension.")
    records = _read_records(stream, safe_name, max_records)
    if not records:
        raise IngestionError("The uploaded file contains no event rows.")
    normalized, rejected = [], []
    for index, record in enumerate(records, start=1):
        try:
            normalized.append(normalize_event(record))
        except ValueError as exc:
            rejected.append({"row": index, "reason": str(exc)})

    alerts_created = []
    duplicates = 0
    accepted = 0
    source_name = safe_name[:255]
    with connect(database) as db:
        db.execute("BEGIN IMMEDIATE")
        for event in normalized:
            if deduplicate and db.execute(
                "SELECT 1 FROM events WHERE fingerprint = ?", (event["fingerprint"],)
            ).fetchone():
                duplicates += 1
                continue
            cursor = db.execute(
                """INSERT INTO events(event_uid,fingerprint,timestamp,source_ip,dest_ip,
                   source_port,dest_port,protocol,event_type,username,hostname,action,result,message,
                   raw_json,source_file,is_synthetic)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event["event_uid"], event["fingerprint"], event["timestamp"], event["source_ip"],
                 event["dest_ip"], event["source_port"], event["dest_port"], event["protocol"],
                 event["event_type"], event["username"], event["hostname"], event["action"],
                 event["result"], event["message"], event["raw_json"], source_name, int(synthetic)),
            )
            if cursor.rowcount == 0:
                duplicates += 1
                continue
            accepted += 1
            alerts_created.extend(detect_and_store(db, cursor.lastrowid, event))
    summary = {
        "records_received": len(records),
        "accepted": accepted,
        "rejected": len(rejected),
        "duplicates": duplicates,
        "validation_errors": rejected[:100],
        "alerts_created": len(alerts_created),
        "incidents_created": sum(alert["incident_created"] for alert in alerts_created),
        "alert_ids": [alert["id"] for alert in alerts_created],
        "incident_ids": list(dict.fromkeys(alert["incident_id"] for alert in alerts_created)),
    }
    LOGGER.info("Import %s: received=%d accepted=%d rejected=%d duplicates=%d alerts=%d",
                source_name, summary["records_received"], accepted, len(rejected), duplicates,
                summary["alerts_created"])
    return summary


DEMO_SCENARIOS = {
    "brute_force": {
        "name": "Brute-force login pattern",
        "description": "Six synthetic failed logins from one documentation-range source.",
    },
    "suspicious_login": {
        "name": "Suspicious login sequence",
        "description": "Repeated synthetic login failures followed by a successful login.",
    },
    "reconnaissance": {
        "name": "Network reconnaissance pattern",
        "description": "Synthetic service-probe and port-scan records.",
    },
    "denied_traffic": {
        "name": "Suspicious denied traffic",
        "description": "Repeated synthetic denied connections to one destination service.",
    },
    "multi_stage": {
        "name": "Multi-stage incident",
        "description": "Related synthetic authentication, privilege, and outbound activity.",
    },
}


def _demo_events(scenario):
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def event(minutes, source, dest, kind, action, username="demo-user", **extra):
        return {
            "timestamp": (now - timedelta(minutes=minutes)).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "source_ip": source, "dest_ip": dest, "event_type": kind, "action": action,
            "username": username, **extra,
        }

    if scenario == "brute_force":
        return [event(6 - index, "198.51.100.24", "10.0.0.8", "authentication",
                      "failed_login", "demo-admin") for index in range(6)]
    if scenario == "suspicious_login":
        attempts = [event(6 - index, "198.51.100.25", "10.0.0.8", "authentication",
                          "failed_login", "demo-admin") for index in range(5)]
        attempts.append(event(0, "198.51.100.25", "10.0.0.8", "authentication",
                              "successful_login", "demo-admin"))
        return attempts
    if scenario == "reconnaissance":
        return [event(4 - index, "203.0.113.77", "10.0.0.5", "port_scan",
                      "service_probe", dest_port=port, protocol="tcp")
                for index, port in enumerate((22, 80, 443, 3389, 445))]
    if scenario == "denied_traffic":
        return [event(5 - index, "192.0.2.55", "10.0.0.9", "network_connection",
                      "denied", dest_port=443, protocol="tcp") for index in range(6)]
    if scenario == "multi_stage":
        return [
            event(8, "198.51.100.44", "10.0.0.8", "authentication", "failed_login", "demo-admin"),
            event(7, "198.51.100.44", "10.0.0.8", "authentication", "failed_login", "demo-admin"),
            event(6, "198.51.100.44", "10.0.0.8", "authentication", "failed_login", "demo-admin"),
            event(5, "198.51.100.44", "10.0.0.8", "authentication", "successful_login", "demo-admin"),
            event(3, "198.51.100.44", "10.0.0.8", "privilege_change", "sudo_elevation", "demo-admin"),
            event(1, "198.51.100.44", "203.0.113.90", "outbound_beacon", "suspicious_egress", "demo-admin"),
        ]
    raise ValueError("Unknown demo scenario.")


def load_demo_scenario(database, scenario):
    requested_scenario = scenario
    if scenario == "port_scan":
        scenario = "reconnaissance"
    if scenario not in DEMO_SCENARIOS:
        raise ValueError("Unknown demo scenario.")
    payload = io.StringIO(json.dumps(_demo_events(scenario)))
    result = ingest_file(database, payload, f"demo-{scenario}.json", synthetic=True)
    result["scenario"] = requested_scenario
    result["name"] = DEMO_SCENARIOS[scenario]["name"]
    result["description"] = DEMO_SCENARIOS[scenario]["description"]
    result["synthetic"] = True
    return result
