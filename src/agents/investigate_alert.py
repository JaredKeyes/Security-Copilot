import sys
from typing import Any, Dict, List

from src.agents.investigation_tools import build_investigation_context

def format_event(event: Dict[str, Any]) -> str:
    return (
        f"- {event.get('event_timestamp')} | "
        f"user={event.get('user_name')} | "
        f"ip={event.get('source_ip_address')} | "
        f"event={event.get('event_name')} | "
        f"resource={event.get('resource_name')} | "
        f"risk={event.get('risk_level')} | "
        f"known_bad_ip={event.get("is_known_bad_ip")} | "
        f"mitre={event.get('mitre_technique')}"
    )

def summarize_evidence(context: Dict[str, Any]) -> List[str]:
    alert = context["alert"]
    related_events = context["related_events"]
    evidence = []

    if alert.get("is_known_bad_ip"):
        evidence.append(
            f"The alert source IP {alert.get('source_ip_address')} is associated with threat intelligence."
        )

    high_risk_events = [
        event for event in related_events
        if event.get("risk_level") == "high"
    ]

    if high_risk_events:
        names = sorted({event.get("event_name") for event in high_risk_events})
        evidence.append(
            f"High-risk events were observed in the related timeline: {', '.join(names)}."
        )

    sensitive_events = [
        event for event in related_events
        if event.get("is_sensitive_event") is True
    ]

    if sensitive_events:
        names = sorted({event.get("event_name") for event in sensitive_events})
        evidence.append(
            f"Sensitive cloud actions were observed: {', '.join(names)}."
        )

    event_names = [event.get("event_name") for event in related_events]

    if "ConsoleLogin" in event_names and "CreateAccessKey" in event_names:
        evidence.append(
            "The timeline contains both ConsoleLogin and CreateAccessKey activity, which may indicate credential compromise or persistence."
        )

    if "StopLogging" in event_names or "DeleteTrail" in event_names:
        evidence.append(
            "The timeline contains CloudTrail logging modification activity, which may indicate defense evasion."
        )
    
    if "AuthorizeSecurityGroupIngress" in event_names and "RunInstances" in event_names:
        evidence.append(
            "The timeline contains security group modification followed by EC2 instance activity, which may indicate suspicious infrastructure changes."
        )

    if not evidence:
        evidence.append(
            "No strong malicious pattern was identified from the available related events, but the alert still requires analyst review."
        )
    
    return evidence

def infer_likely_pattern(context: Dict[str, Any]) -> str:
    related_events = context["related_events"]
    event_names = {event.get("event_name") for event in related_events}

    if {"ConsoleLogin", "ListBuckets", "GetObject", "CreateAccessKey", "AssumeRole"}.issubset(event_names):
        return "Possible AWS credential compromise with discovery, data access, persistence, and privilege escalation."

    if {"AssumeRole", "StopLogging", "DeleteTrail"}.issubset(event_names):
        return "Possible CloudTrail tampering or defense evasion after privileged role activity."

    if {"AssumeRole", "AuthorizeSecurityGroupIngress", "RunInstances"}.issubset(event_names):
        return "Possible service account abuse or suspicious infrastructure modification."

    if {"ListBuckets", "GetObject"}.issubset(event_names):
        return "Possible S3 discovery and data access activity."

    return "Unclear pattern. Additional analyst review is required."