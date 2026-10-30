def analyze(source_ip, alerts):
    rules = sorted({alert["rule_id"] for alert in alerts})
    return {
        "agent": "Threat Intelligence Agent",
        "finding": f"Source {source_ip or 'unknown'} has {len(rules)} distinct observed detection rule(s). "
                   "No external reputation lookup was performed.",
        "evidence": [f"alert:{alert['id']}" for alert in alerts],
    }


class ThreatIntelligenceAgent:
    agent_id = "threat_intelligence_agent"
    name = "Threat Intelligence Agent"
    responsibility = "Report available local context without claiming external reputation."

    def run(self, context):
        return analyze(context.incident["source_ip"], context.alerts)
