def report(incident, agents):
    return {
        "headline": incident["title"],
        "assessment": incident["summary"],
        "agent_findings": agents,
        "human_review_required": True,
        "response_actions": [],
    }


class ReportingAgent:
    agent_id = "reporting_agent"
    name = "Reporting Agent"
    responsibility = "Compile evidence-grounded triage notes and limitations."

    def run(self, context, agents):
        result = report(context.incident, agents)
        result["severity"] = context.incident["severity"]
        result["severity_rationale"] = context.incident.get("severity_rationale", "")
        result["limitations"] = [
            "Rule-based findings are triage indicators, not proof of compromise.",
            "No external threat intelligence provider is configured.",
            "Asset criticality and business impact are not available.",
        ]
        result["recommended_next_steps"] = [
            "Review cited source events and associated alerts.",
            "Confirm account, host, and network activity with authoritative logs.",
            "Record analyst decisions before any consequential response.",
        ]
        return result
