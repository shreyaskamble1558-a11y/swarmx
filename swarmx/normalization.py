import hashlib
import ipaddress
import json
import uuid
from datetime import datetime, timezone


ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "event_time", "created_at"),
    "source_ip": ("source_ip", "src_ip", "src", "source", "ip"),
    "dest_ip": ("dest_ip", "destination_ip", "dst_ip", "dst", "destination"),
    "source_port": ("source_port", "src_port", "sport"),
    "dest_port": ("destination_port", "dest_port", "dst_port", "dport"),
    "protocol": ("protocol", "transport"),
    "event_type": ("event_type", "type", "event", "category"),
    "username": ("username", "user", "account", "principal"),
    "hostname": ("hostname", "host", "computer", "device"),
    "action": ("action", "activity"),
    "result": ("result", "outcome", "status"),
    "message": ("message", "description", "details"),
}
MAX_FIELD_LENGTH = 2000


def _text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        raise ValueError("Event fields must contain plain text or numeric values.")
    return str(value).strip()[:MAX_FIELD_LENGTH]


def _port(value, field):
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer from 1 to 65535.")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer from 1 to 65535.") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{field} must be an integer from 1 to 65535.")
    return port


def normalize_event(record):
    if not isinstance(record, dict):
        raise ValueError("Each event must be a JSON object or CSV row.")
    source = {str(key).strip().lower(): value for key, value in record.items()}
    result = {}
    for field, aliases in ALIASES.items():
        value = next((source[name] for name in aliases if source.get(name) not in (None, "")), "")
        result[field] = _text(value)
    if not result["source_ip"]:
        raise ValueError("Missing source IP.")
    if not result["event_type"]:
        raise ValueError("Missing event type.")
    try:
        result["source_ip"] = str(ipaddress.ip_address(result["source_ip"]))
        if result["dest_ip"]:
            result["dest_ip"] = str(ipaddress.ip_address(result["dest_ip"]))
    except ValueError as exc:
        raise ValueError("Source and destination addresses must be valid IPv4 or IPv6 addresses.") from exc
    result["source_port"] = _port(result["source_port"], "Source port")
    result["dest_port"] = _port(result["dest_port"], "Destination port")
    result["timestamp"] = normalize_timestamp(result["timestamp"])
    result["raw_json"] = json.dumps(record, ensure_ascii=False, default=str)
    result["event_uid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, _fingerprint_fields(result)))
    result["fingerprint"] = hashlib.sha256(_fingerprint_fields(result).encode("utf-8")).hexdigest()
    return result


def _fingerprint_fields(event):
    stable_fields = ("timestamp", "event_type", "source_ip", "dest_ip", "source_port",
                     "dest_port", "protocol", "username", "hostname", "action", "result", "message")
    return json.dumps([event.get(field) for field in stable_fields], ensure_ascii=False, separators=(",", ":"))


def normalize_timestamp(value):
    if not value:
        raise ValueError("Missing timestamp.")
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for pattern in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, pattern).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        else:
            raise ValueError("Timestamp must be ISO-8601 or a supported common date format.")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
