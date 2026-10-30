from dataclasses import dataclass
from datetime import datetime, timezone

from swarmx.agents.detection_agent import DetectionAgent
from swarmx.agents.evidence_validator import EvidenceValidationAgent
from swarmx.agents.incident_analysis_agent import IncidentAnalysisAgent
from swarmx.agents.reporting_agent import ReportingAgent
from swarmx.agents.threat_intelligence_agent import ThreatIntelligenceAgent


@dataclass(frozen=True)
class AnalysisContext:
    job_id: str
    incident: dict
    alerts: list
    events: list


def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class CoordinatorAgent:
    agent_id = "coordinator"
    name = "Coordinator Agent"
    responsibility = "Run specialist analyses in order and compile an analyst-facing result."

    def __init__(self):
        self.agents = (
            DetectionAgent(),
            ThreatIntelligenceAgent(),
            IncidentAnalysisAgent(),
        )
        self.validator = EvidenceValidationAgent()
        self.reporter = ReportingAgent()

    def run(self, incident, alerts, events, job_id):
        context = AnalysisContext(job_id, incident, alerts, events)
        coordinator_started = _timestamp()
        runs = []
        raw_findings = []
        for agent in self.agents:
            started = _timestamp()
            try:
                finding = agent.run(context)
                raw_findings.append(finding)
                runs.append({
                    "agent_id": agent.agent_id, "agent": agent.name, "status": "Completed",
                    "started_at": started, "completed_at": _timestamp(), "result": finding,
                    "error": "",
                })
            except Exception as exc:
                runs.append({
                    "agent_id": agent.agent_id, "agent": agent.name, "status": "Failed",
                    "started_at": started, "completed_at": _timestamp(), "result": {},
                    "error": str(exc)[:500],
                })
        validation_started = _timestamp()
        validated_findings = self.validator.run(raw_findings, context)
        runs.append({
            "agent_id": self.validator.agent_id, "agent": self.validator.name,
            "status": "Completed", "started_at": validation_started,
            "completed_at": _timestamp(), "result": {"findings": validated_findings},
            "error": "",
        })
        reporting_started = _timestamp()
        report = self.reporter.run(context, validated_findings)
        runs.append({
            "agent_id": self.reporter.agent_id, "agent": self.reporter.name,
            "status": "Completed", "started_at": reporting_started,
            "completed_at": _timestamp(), "result": {
                "headline": report["headline"], "assessment": report["assessment"],
                "limitations": report["limitations"],
            }, "error": "",
        })
        report["agent_runs"] = runs
        report["job_id"] = job_id
        report["validation_status"] = (
            "Validated" if all(item["validated"] for item in validated_findings)
            else "Needs Review"
        )
        report["agent_findings"] = validated_findings
        report["agent_runs"] = runs
        runs.append({
            "agent_id": self.agent_id, "agent": self.name, "status": "Completed",
            "started_at": coordinator_started, "completed_at": _timestamp(),
            "result": {"job_id": job_id, "status": report["validation_status"]}, "error": "",
        })
        return report


def coordinate(incident, alerts, events=None, job_id="local-analysis"):
    return CoordinatorAgent().run(incident, alerts, events or [], job_id)
