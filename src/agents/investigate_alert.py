import sys
from typing import Any, Dict, List

from src.agents.investigation_tools import build_investigation_context
from src.llm.generate_report import generate_report_llm
from src.guardrails.security_guardrails import apply_guardrails, format_guardrail_result
from src.monitoring.monitoring_logger import Timer, log_error, log_investigation_request

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

        draft_report = generate_report_llm(context)

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
            ip_timeline_count=len(context.get("ip_timeline", [])),
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
