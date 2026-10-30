def analyze(alerts):
    return {
        "agent": "Detection Agent",
        "finding": f"{len(alerts)} rule-based alert(s) are linked to this incident.",
        "evidence": [f"alert:{alert['id']}" for alert in alerts],
    }


class DetectionAgent:
    agent_id = "detection_agent"
    name = "Detection Agent"
    responsibility = "Summarize stored rule detections and their event evidence."

    def run(self, context):
        return analyze(context.alerts)
