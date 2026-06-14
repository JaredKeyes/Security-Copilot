import sys
from typing import Any, Dict, List

from src.agents.investigation_tools import build_investigation_context
from src.guardrails.security_guardrails import apply_guardrails, format_guardrail_result
from src.monitoring.monitoring_logger import Timer, log_error, log_investigation_request

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
        event for event in related_events if event.get("risk_level") == "high"
    ]

    if high_risk_events:
        names = sorted({event.get("event_name") for event in high_risk_events})
        evidence.append(
            f"High-risk events were observed in the related timeline: {', '.join(names)}."
        )

    sensitive_events = [
        event for event in related_events if event.get("is_sensitive_event") is True
    ]

    if sensitive_events:
        names = sorted({event.get("event_name") for event in sensitive_events})
        evidence.append(f"Sensitive cloud actions were observed: {', '.join(names)}.")

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

    if {
        "ConsoleLogin",
        "ListBuckets",
        "GetObject",
        "CreateAccessKey",
        "AssumeRole",
    }.issubset(event_names):
        return "Possible AWS credential compromise with discovery, data access, persistence, and privilege escalation."

    if {"AssumeRole", "StopLogging", "DeleteTrail"}.issubset(event_names):
        return "Possible CloudTrail tampering or defense evasion after privileged role activity."

    if {"AssumeRole", "AuthorizeSecurityGroupIngress", "RunInstances"}.issubset(
        event_names
    ):
        return (
            "Possible service account abuse or suspicious infrastructure modification."
        )

    if {"ListBuckets", "GetObject"}.issubset(event_names):
        return "Possible S3 discovery and data access activity."

    return "Unclear pattern. Additional analyst review is required."


def recommend_next_steps(context: Dict[str, Any]) -> List[str]:
    alert = context["alert"]
    related_events = context["related_events"]
    event_names = {event.get("event_name") for event in related_events}

    steps = [
        "Confirm whether the activity was expected or approved.",
        "Preserve CloudTrail, GuardDuty, IAM, and related investigation evidence before making changes.",
        "Review the involved principal's recent activity, permissions, MFA status, and access keys.",
    ]

    if alert.get("is_known_bad_ip"):
        steps.append(
            "Investigate the source IP reputation and check whether it accessed other users or resources."
        )

    if "CreateAccessKey" in event_names:
        steps.append(
            "Review newly created access keys and rotate or disable suspicious credentials with approval."
        )

    if "GetObject" in event_names or "ListBuckets" in event_names:
        steps.append(
            "Review S3 bucket/object access to determine whether sensitive data was accessed."
        )

    if "StopLogging" in event_names or "DeleteTrail" in event_names:
        steps.append(
            "Verify CloudTrail logging is enabled and restrict permissions that allow logging changes."
        )

    if "AuthorizeSecurityGroupIngress" in event_names:
        steps.append(
            "Review security group rules and revert unauthorized exposure after approval."
        )

    if "RunInstances" in event_names:
        steps.append(
            "Inspect newly launched EC2 instances and isolate suspicious resources if needed."
        )

    steps.append(
        "Escalate to incident response if unauthorized access, persistence, data access, or logging tampering is confirmed."
    )

    return steps


def calculate_confidence(context: Dict[str, Any]) -> str:
    related_events = context["related_events"]

    score = 0

    if context["alert"].get("is_known_bad_ip"):
        score += 2

    high_risk_count = sum(
        1 for event in related_events if event.get("risk_level") == "high"
    )
    sensitive_count = sum(
        1 for event in related_events if event.get("is_sensitive_event") is True
    )

    score += min(high_risk_count, 3)
    score += min(sensitive_count, 3)

    if len(related_events) >= 3:
        score += 1

    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"

    return "Low"


def format_runbook_sources(context: Dict[str, Any]) -> List[str]:
    sources = []

    for result in context["runbook_context"]:
        metadata = result["metadata"]
        sources.append(
            f"- {metadata.get('file_name')} chunk {metadata.get('chunk_index')}"
            f"(distance={result.get('distance')})"
        )

    return sources


def generate_investigation_report(finding_id: str) -> str:
    timer = Timer()
    
    try:
        context = build_investigation_context(finding_id)

        if "error" in context:
            latency = timer.elapsed()

            log_investigation_request(
                finding_id=finding_id,
                status="failed",
                latency_seconds=latency,
                error=context["error"]
            )

            return f"Investigation failed: {context['error']}"

        alert = context["alert"]
        user_risk = context["user_risk_summary"]
        ip_reputation = context["ip_reputation_summary"]

        evidence = summarize_evidence(context)
        likely_pattern = infer_likely_pattern(context)
        next_steps = recommend_next_steps(context)
        confidence = calculate_confidence(context)
        runbook_sources = format_runbook_sources(context)

        report = []

        report.append("=" * 100)
        report.append("Investigation Report")
        report.append("=" * 100)

        report.append("\n## Alert Overview")
        report.append(f"Finding ID: {alert.get('finding_id')}")
        report.append(f"Finding Type: {alert.get('finding_type')}")
        report.append(f"Title: {alert.get('title')}")
        report.append(f"Severity: {alert.get('severity')} ({alert.get('severity_label')})")
        report.append(f"User: {alert.get('user_name')}")
        report.append(f"Source IP: {alert.get('source_ip_address')}")
        report.append(f"Resource: {alert.get('resource_name')}")
        report.append(f"Related Event: {alert.get('event_name')}")
        report.append(f"MITRE Technique: {alert.get('mitre_technique')}")

        report.append("\n## Likely Pattern")
        report.append(likely_pattern)

        report.append("\n## Evidence Summary")
        for item in evidence:
            report.append(f"- {item}")

        report.append("\n## Related Event Timeline")
        for event in context["related_events"]:
            report.append(format_event(event))

        report.append("\n## User Risk Summary")
        report.append(str(user_risk) if user_risk else "No user risk summary found.")

        report.append("\n## IP Reputation Summary")
        report.append(
            str(ip_reputation) if ip_reputation else "No IP reputation summary found."
        )

        report.append("\n## Relevant Runbook Sources")
        if runbook_sources:
            report.extend(runbook_sources)
        else:
            report.append("No relevant runbook context retrieved.")

        report.append("\n## Recommended Next Steps")
        for step in next_steps:
            report.append(f"- {step}")

        report.append("\n## Confidence")
        report.append(confidence)

        report.append("\n## Safety Note")
        report.append(
            "This report is an analyst decision-support artifact. Destructive containment actions "
            "such as disabling credentials, modifying security groups, or isolating resources should "
            "require human approval."
        )

        draft_report = "\n".join(report)

        guardrail_result = apply_guardrails(draft_report, context)
        guardrailed_report = guardrail_result["masked_report"]
        guardrailed_report += format_guardrail_result(guardrail_result)

        latency = timer.elapsed()

        retrieved_runbook_sources = [
            result.get("metadata", {}).get("file_name")
            for result in context.get("runbook_context", [])
            if result.get("metadata", {}).get("file_name")
        ]

        log_investigation_request(
            finding_id=finding_id,
            status="success",
            latency_seconds=latency,
            alert=alert,
            runbook_sources=sorted(set(retrieved_runbook_sources)),
            guardrail_status=guardrail_result["status"],
            report_length_chars=len(guardrailed_report),
            related_event_count=len(context.get("related_events", [])),
            user_timeline_count=len(context.get("user_timeline", [])),
            ip_timeline_count=len(context.get("ip_tmieline", [])),
        )

        return guardrailed_report

    except Exception as exc:
        latency = timer.elapsed()

        log_error(
            component="generate_investigation_report",
            finding_id=finding_id,
            error_message=str(exc),
        )

        log_investigation_request(
            finding_id=finding_id,
            status="error",
            latency_seconds=latency,
            error=str(exc),
        )
    
    raise

def main():
    if len(sys.argv) < 2:
        finding_id = "gd-seeded-0001"
    else:
        finding_id = sys.argv[1]

    print(generate_investigation_report(finding_id))


if __name__ == "__main__":
    main()
