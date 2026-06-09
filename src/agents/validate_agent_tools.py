from src.agents.investigation_tools import build_investigation_context

def main():
    finding_id = "gd-seeded-0001"

    context = build_investigation_context(finding_id)

    if "error" in context:
        print(context["error"])
        return

    print("\n=== Alert ===")
    print(context["alert"])

    print("\n=== Related Events Count ===")
    print(len(context["related_events"]))

    print("\n=== User Timeline Count ===")
    print(len(context["user_timeline"]))

    print("\n=== IP Timeline Count ===")
    print(len(context["ip_timeline"]))

    print("\n=== User Risk Summary ===")
    print(context["user_risk_summary"])

    print("\n=== IP Reputation Summary ===")
    print(context["ip_reputation_summary"])

    print("\n=== Retrieved Runbook Source ===")
    for result in context["runbook_context"]:
        print(
            result["metadata"]["file_name"],
            "chunk",
            result["metadata"]["chunk_index"],
            "distance",
            result["distance"],
        )

if __name__ == "__main__":
    main()