def validate(analysis, alerts):
    known = {f"alert:{alert['id']}" for alert in alerts}
    validated = []
    for item in analysis:
        supported = [reference for reference in item["evidence"] if reference in known]
        validated.append({
            **item,
            "evidence": supported,
            "validated": bool(supported) or not alerts,
        })
    return validated


class EvidenceValidationAgent:
    agent_id = "evidence_validator"
    name = "Evidence Validation Agent"
    responsibility = "Check agent evidence references against loaded incident alerts."

    def run(self, findings, context):
        validated = validate(findings, context.alerts)
        for item in validated:
            item["validation_status"] = "Validated" if item["validated"] else "Unsupported"
        return validated
