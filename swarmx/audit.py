import json

from swarmx.database import connect


def record_audit(database, action, target, details):
    with connect(database) as db:
        db.execute(
            "INSERT INTO audit_log(action,target,details) VALUES(?,?,?)",
            (action, target, json.dumps(details, ensure_ascii=False, default=str)),
        )
