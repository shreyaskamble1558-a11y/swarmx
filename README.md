# SwarmX

SwarmX is a local-first, explainable security event triage dashboard built with Flask, SQLite, and vanilla JavaScript. It is intended for education and defensive SOC demonstrations, not as a replacement for a production SIEM.

## Requirements and launch

- Windows 10/11 and Python 3.11 or a compatible Python 3 release
- Run `run_windows.bat`, or run `py -m venv .venv`, activate it, install `requirements.txt`, then use `py app.py`.
- Open http://127.0.0.1:5000. Data is stored in `instance/swarmx.db`.
- Run tests with `py -m pytest`.

The web interface uses Chart.js from a public CDN. Its APIs and event processing are local. If the browser is offline or the CDN is unavailable, text metrics and severity counts remain available and the dashboard displays a chart fallback.

## Capabilities

- Import CSV and JSON events with field alias normalization, timestamp validation, row-level rejection details, and a 5 MB request limit.
- Explainable detections for repeated authentication failures, malware indicators, privilege changes, port scans, and suspicious egress.
- Evidence-linked alerts, source-IP incident correlation, severity aggregation, and SQLite audit history.
- Server-side search, filters, and pagination for event, alert, and incident queues.
- Records are retained indefinitely; there is no automatic deletion or retention scheduler.
- Local specialist agents produce bounded triage summaries. Evidence references are checked against stored alerts; no paid AI service or external threat-intelligence lookup is used.
- Incident status/severity management, analyst notes, JSON incident reports, event CSV exports, and a data-derived network graph.
- Synthetic brute-force, malware, and port-scan scenarios for demonstrations.

Incident analysis is advisory. SwarmX does not execute containment or remediation actions; consequential response always requires human review.

## Architecture and data flow

1. Flask receives an uploaded CSV/JSON file and parses each row independently.
2. Normalization maps common field aliases, canonicalizes IPv4/IPv6 addresses, and converts timestamps to UTC. Invalid rows are reported and skipped.
3. SQLite stores each accepted source event. The explainable detection engine evaluates it and creates evidence-linked alerts when rules match.
4. Alerts from the same source IP are attached to an open/investigating incident created within the previous 24 hours. Incident severity rises to the highest linked signal.
5. Dashboard, event, incident, and network APIs query SQLite. Three specialist analysis agents provide local findings; an evidence validator checks alert references before the result is shown.
6. An analyst can update case severity/status, add notes, and export reports. No automatic response action is performed.

### Detection rules and preliminary severity

| Rule | Match conditions | Initial severity |
| --- | --- | --- |
| Repeated authentication failures | At least five failed/denied authentication events from one source IP in a ten-minute window | High |
| Malware indicator | Event type/action contains malware, ransomware, trojan, virus, or malicious-file indicator text | Critical |
| Privilege change | Event type/action contains privilege, sudo, admin grant, role change, or elevation text | High |
| Port/service scan | Event type/action identifies a port/network scan or service probe | Medium |
| Suspicious egress | Event type/action identifies outbound, egress, exfiltration, beacon, or command-and-control activity | Medium |
| Authentication failure | Event type/action identifies a failed or denied authentication attempt below the repeated-failure threshold | Low |

These are demonstration rules, not claims of confirmed malicious activity. Rule descriptions and source event references are retained with alerts for review.

### Input format

JSON may be a single event object, an array, or an object containing an `events`/`logs` array. CSV uses headers. `source_ip` (also `src_ip`, `src`, `source`, or `ip`) and `event_type` (also `type`, `event`, or `category`) are required. Source and destination values must be valid IPv4/IPv6 addresses. Timestamp aliases are `timestamp`, `time`, `datetime`, and `event_time`; accepted timestamp values include ISO-8601 and common year-first/month-first date formats. Missing timestamps default to current UTC time. Destination, username, and action fields are optional.

Example CSV:

```csv
timestamp,source_ip,dest_ip,event_type,username,action
2026-10-24T10:00:00Z,198.51.100.24,10.0.0.8,authentication,analyst,failed_login
```

### SQLite tables

- `events`: normalized event fields, source filename, and original event JSON.
- `incidents`: case title, summary, severity, status, source IP, and timestamps.
- `alerts`: detection rule, severity, description, evidence references, and related event/incident IDs.
- `notes`: analyst-authored incident notes.
- `audit_log`: ingestion, demo, analyst updates, and analysis activity.

### Demonstration workflow

1. Start SwarmX and select one of the built-in synthetic scenarios on the overview, or upload a prepared CSV/JSON file.
2. Review the incident queue and open an incident to inspect linked alerts and source evidence.
3. Run local agent analysis and check the validated evidence references.
4. Change the case status/severity, add an analyst note, and download the JSON incident report or event CSV.
5. Use the network map to inspect observed source/destination relationships from the stored events.

Run the automated tests with `py -m pytest`. Tests use temporary SQLite databases and exercise ingestion, detection/correlation, analysis validation, incident updates, notes, reports, and network data.

## API overview

- `GET /api/health`, `/api/dashboard`, `/api/events`, `/api/incidents`, `/api/network`
- `POST /api/ingest` (multipart form field `file`) and `POST /api/demo`
- `GET /api/incidents/<id>`, `PATCH /api/incidents/<id>`
- `POST /api/incidents/<id>/notes`, `POST /api/incidents/<id>/analyze`
- `GET /api/incidents/<id>/report`, `GET /api/export/events.csv`
- Versioned list endpoints under `/api/v1/` support `page`, `limit`, and relevant search/filter query parameters; use `/api/v1/events/types` for available event categories.

## Security and deployment

SwarmX is intended to bind to `127.0.0.1` for a single-user demonstration. State-changing requests require a session-bound CSRF token and reject mismatched origins or cross-site Fetch Metadata. Session cookies are HttpOnly and SameSite=Strict; the default signing key is randomly generated at process startup. Set `SWARMX_SECRET_KEY` to a long, random value if a stable key is needed, and set `SWARMX_COOKIE_SECURE=true` only when serving over HTTPS.

CSRF protection does not provide user authentication or authorization. Do not expose this application to a network or use it with sensitive production telemetry until authentication, role-based access control, secure secret management, HTTPS, and a production WSGI server are configured. The built-in Flask server is for local development only.
