from src.agents.investigate_alert import generate_investigation_report
from src.agents.investigation_tools import build_investigation_context

FINDINGS_IDS = [
    "gd-seeded-0001",
    "gd-seeded-0002",
    "gd-seeded-0003",
]


def validate_context(finding_id: str) -> dict:
    context = build_investigation_context(finding_id)

    if "error" in context:
        return {
            "finding_id": finding_id,
            "alert_found": False,
            "related_events_found": False,
            "user_risk_found": False,
            "ip_reputation_found": False,
            "runbook_context_found": False,
            "report_generated": False,
        }

    report = generate_investigation_report(finding_id)

    return {
        "finding_id": finding_id,
        "alert_found": context.get("alert") is not None,
        "related_events_found": len(context.get("related_events", [])) > 0,
        "user_risk_found": context.get("user_risk_summary") is not None,
        "ip_reputation_found": context.get("ip_reputation_summary") is not None,
        "runbook_context_found": len(context.get("runbook_context", [])) > 0,
        "report_generated": "Investigation Report" in report,
    }


def main():
    results = []

    for finding_id in FINDINGS_IDS:
        result = validate_context(finding_id)
        results.append(result)

        print("\n" + "=" * 100)
        print(f"Validation for {finding_id}")
        print("=" * 100)

        for key, value in result.items():
            if key != "finding_id":
                print(f"{key}: {'PASS' if value else 'FAIL'}")

    total_checks = 0
    passed_checks = 0

    for result in results:
        for key, value in result.items():
            if key == "finding_id":
                continue

            total_checks += 1
            if value:
                passed_checks += 1

    print("\n" + "=" * 100)
    print("Agent workflow validation summary")
    print("=" * 100)
    print(f"Passed checks: {passed_checks}/{total_checks}")


if __name__ == "__main__":
    main()
