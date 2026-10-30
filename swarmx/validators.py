from datetime import datetime


def pagination(args, default_limit=50, maximum_limit=200):
    try:
        page = int(args.get("page", 1))
        limit = int(args.get("limit", default_limit))
    except (TypeError, ValueError) as exc:
        raise ValueError("page and limit must be integers.") from exc
    if page < 1 or limit < 1:
        raise ValueError("page and limit must be positive integers.")
    limit = min(limit, maximum_limit)
    return page, limit, (page - 1) * limit


def iso_timestamp(value, name):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).isoformat()
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp.") from exc


def csv_safe(value):
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text
