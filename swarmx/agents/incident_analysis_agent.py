from collections import Counter


def analyze(alerts):
    rules = Counter(alert["rule_id"] for alert in alerts)
    summary = ", ".join(f"{name} ({count})" for name, count in sorted(rules.items())) or "no alerts"
    return {
        "agent": "Incident Analysis Agent",
        "finding": f"Observed incident pattern: {summary}. Treat this as triage guidance, not a confirmed attribution.",
        "evidence": [f"alert:{alert['id']}" for alert in alerts],
    }


class IncidentAnalysisAgent:
    agent_id = "incident_analysis_agent"
    name = "Incident Analysis Agent"
    responsibility = "Summarize observed events and construct an evidence-referenced timeline."

    def run(self, context):
        finding = analyze(context.alerts)
        finding["timeline"] = [
            {"timestamp": event.get("timestamp"), "event_id": event.get("id"),
             "event_type": event.get("event_type"), "source_ip": event.get("source_ip"),
             "dest_ip": event.get("dest_ip"), "action": event.get("action")}
            for event in context.events
        ]
        finding["recommendations"] = [
            "Review authentication and endpoint records for the referenced time window.",
            "Verify whether the source and affected account activity is expected.",
            "Preserve supporting logs before taking any response action.",
        ]
        return finding
