SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def highest_severity(values):
    return max(values, key=lambda value: SEVERITY_RANK[value], default="Low")


def preliminary_severity(rule_id):
    return {
        "brute_force": "High",
        "malware_indicator": "Critical",
        "privilege_change": "High",
        "port_scan": "Medium",
        "suspicious_egress": "Medium",
        "auth_failure": "Low",
    }.get(rule_id, "Low")


def classify_severity(base, event_count=1, rule_id=""):
    rank = SEVERITY_RANK[base]
    factors = [f"Detection rule {rule_id or 'unknown'} has a base severity of {base}."]
    if event_count >= 5 and rank < SEVERITY_RANK["High"]:
        rank = SEVERITY_RANK["High"]
        factors.append(f"{event_count} related evidence events raised the triage priority.")
    severity = next(name for name, value in SEVERITY_RANK.items() if value == rank)
    return {
        "severity": severity,
        "confidence": round(min(0.95, 0.55 + min(event_count, 10) * 0.035), 2),
        "score_basis": f"Rule base severity {base}; related evidence count {event_count}.",
        "factors": factors,
        "missing_information": ["Asset criticality and business impact are not configured."],
        "explanation": " ".join(factors) + " Severity is a deterministic triage category, not a calibrated probability.",
        "analyst_review_required": True,
    }
