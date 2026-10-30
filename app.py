import logging
import hmac
import secrets
from urllib.parse import urlsplit
from flask import Flask, jsonify, render_template, request, send_file, session
from werkzeug.utils import secure_filename

from config import Config
from swarmx.audit import record_audit
from swarmx.database import connect, init_db
from swarmx.ingestion import IngestionError, ingest_file, load_demo_scenario
from swarmx.incident_manager import add_note, analyze_incident, update_incident
from swarmx.reporting import export_events_csv, export_incident_report
from swarmx.services import dashboard_data, event_list, incident_list, network_data


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Strict")
    app.config.setdefault("SESSION_COOKIE_SECURE", False)
    init_db(app.config["DATABASE"])
    from swarmx.api import api_v1
    app.register_blueprint(api_v1)
    logging.getLogger("swarmx").setLevel(logging.INFO)

    @app.before_request
    def protect_state_changes():
        host = urlsplit(f"//{request.host}").hostname
        if host not in app.config["ALLOWED_HOSTS"]:
            return jsonify({"error": "This local SwarmX instance only accepts loopback hosts."}), 400
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None
        expected = session.get("_csrf_token")
        supplied = request.headers.get("X-CSRF-Token", "")
        origin = request.headers.get("Origin")
        fetch_site = request.headers.get("Sec-Fetch-Site")
        if not expected or not hmac.compare_digest(expected, supplied):
            return jsonify({"error": "Missing or invalid CSRF token. Reload the local dashboard and try again."}), 403
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            return jsonify({"error": "Cross-origin state changes are not allowed."}), 403
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            return jsonify({"error": "Cross-site state changes are not allowed."}), 403
        return None

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response

    @app.get("/")
    def index():
        csrf_token = session.setdefault("_csrf_token", secrets.token_urlsafe(32))
        return render_template("index.html", csrf_token=csrf_token)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "application": "SwarmX"})

    @app.get("/api/dashboard")
    def dashboard():
        return jsonify(dashboard_data(app.config["DATABASE"]))

    @app.get("/api/events")
    def events():
        try:
            return jsonify(event_list(app.config["DATABASE"], request.args)["items"])
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/incidents")
    def incidents():
        try:
            return jsonify(incident_list(app.config["DATABASE"], request.args)["items"])
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/incidents/<int:incident_id>")
    def incident_detail(incident_id):
        with connect(app.config["DATABASE"]) as db:
            incident = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if not incident:
                return jsonify({"error": "Incident not found"}), 404
            alerts = db.execute(
                """SELECT a.*, e.timestamp, e.source_ip, e.dest_ip, e.event_type, e.username
                   FROM alerts a JOIN events e ON e.id = a.event_id
                   WHERE a.incident_id = ? ORDER BY a.id""",
                (incident_id,),
            ).fetchall()
            notes = db.execute(
                "SELECT * FROM notes WHERE incident_id = ? ORDER BY created_at DESC",
                (incident_id,),
            ).fetchall()
        return jsonify({"incident": dict(incident), "alerts": [dict(row) for row in alerts],
                        "notes": [dict(row) for row in notes]})

    @app.get("/api/network")
    def network():
        try:
            return jsonify(network_data(app.config["DATABASE"], request.args.get("limit", 100), request.args))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/ingest")
    def ingest():
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            return jsonify({"error": "Choose a CSV or JSON file to upload."}), 400
        try:
            result = ingest_file(app.config["DATABASE"], uploaded.stream, uploaded.filename,
                                 max_records=app.config["MAX_EVENT_COUNT"])
        except IngestionError as exc:
            record_audit(app.config["DATABASE"], "file_ingest_failed", secure_filename(uploaded.filename)[:255],
                         {"error": str(exc)[:200]})
            return jsonify({"error": str(exc)}), 400
        record_audit(app.config["DATABASE"], "file_ingested", secure_filename(uploaded.filename)[:255],
                     {"accepted": result["accepted"], "rejected": result["rejected"],
                      "duplicates": result["duplicates"]})
        return jsonify(result), 201

    @app.post("/api/demo")
    def demo():
        payload = request.get_json(silent=True)
        if payload is not None and not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a JSON object."}), 400
        scenario = (payload or {}).get("scenario", "brute_force")
        try:
            result = load_demo_scenario(app.config["DATABASE"], scenario)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        record_audit(app.config["DATABASE"], "demo_loaded", scenario, result)
        return jsonify(result), 201

    @app.patch("/api/incidents/<int:incident_id>")
    def incident_update(incident_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a JSON object."}), 400
        try:
            updated = update_incident(app.config["DATABASE"], incident_id, payload)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if updated is None:
            return jsonify({"error": "Incident not found"}), 404
        record_audit(app.config["DATABASE"], "incident_updated", str(incident_id), payload)
        return jsonify(updated)

    @app.post("/api/incidents/<int:incident_id>/notes")
    def incident_note(incident_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a JSON object."}), 400
        try:
            note = add_note(app.config["DATABASE"], incident_id, payload.get("text", ""))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if note is None:
            return jsonify({"error": "Incident not found"}), 404
        record_audit(app.config["DATABASE"], "incident_note_added", str(incident_id), {})
        return jsonify(note), 201

    @app.post("/api/incidents/<int:incident_id>/analyze")
    def incident_analyze(incident_id):
        try:
            analysis = analyze_incident(app.config["DATABASE"], incident_id)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if analysis is None:
            return jsonify({"error": "Incident not found"}), 404
        record_audit(app.config["DATABASE"], "incident_analyzed", str(incident_id), {})
        return jsonify(analysis)

    @app.get("/api/incidents/<int:incident_id>/report")
    def incident_report(incident_id):
        report_data = export_incident_report(app.config["DATABASE"], incident_id)
        if not report_data:
            return jsonify({"error": "Incident not found"}), 404
        return send_file(report_data, as_attachment=True, download_name=f"swarmx-incident-{incident_id}.json",
                         mimetype="application/json")

    @app.get("/api/export/events.csv")
    def events_export():
        return send_file(export_events_csv(app.config["DATABASE"]), as_attachment=True,
                         download_name="swarmx-events.csv", mimetype="text/csv")

    @app.errorhandler(413)
    def file_too_large(_error):
        record_audit(app.config["DATABASE"], "file_ingest_failed", "upload",
                     {"error": "File exceeded configured upload limit."})
        return jsonify({"error": "File exceeds the 5 MB upload limit."}), 413

    @app.errorhandler(500)
    def unexpected_error(error):
        app.logger.exception("Unexpected request failure: %s", error)
        return jsonify({"error": "An internal application error occurred. Check the local server log."}), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
