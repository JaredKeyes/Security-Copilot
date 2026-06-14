import json
from pathlib import Path
from typing import Any, Dict, List


MONITORING_DIR = Path("data/gold/monitoring")
INVESTIGATION_LOG_PATH = MONITORING_DIR / "investigation_requests.jsonl"
EVALUATION_LOG_PATH = MONITORING_DIR / "evaluation_runs.jsonl"
ERROR_LOG_PATH = MONITORING_DIR / "errors.jsonl"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    rows = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            rows.append(json.loads(line))

    return rows


def print_section(title: str) -> None:
    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)


def summarize_investigations(rows: List[Dict[str, Any]]) -> None:
    print_section("Investigation Request Summary")

    if not rows:
        print("No investigation request logs found.")
        return

    total = len(rows)
    successes = sum(1 for row in rows if row.get("status") == "success")
    failures = total - successes

    latencies = [
        row.get("latency_seconds")
        for row in rows
        if isinstance(row.get("latency_seconds"), (int, float))
    ]

    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    guardrail_status_counts = {}

    for row in rows:
        status = row.get("guardrail_status", "UNKNOWN")
        guardrail_status_counts[status] = guardrail_status_counts.get(status, 0) + 1

    print(f"Total investigations: {total}")
    print(f"Successful investigations: {successes}")
    print(f"Failed investigations: {failures}")
    print(f"Average latency seconds: {round(avg_latency, 4)}")
    print(f"Guardrail statuses: {guardrail_status_counts}")

    print("\nRecent investigations:")
    for row in rows[-5:]:
        alert = row.get("alert_summary", {})
        print(
            f"- {row.get('timestamp')} | "
            f"finding={row.get('finding_id')} | "
            f"status={row.get('status')} | "
            f"guardrail={row.get('guardrail_status')} | "
            f"latency={row.get('latency_seconds')}s | "
            f"user={alert.get('user_name')} | "
            f"ip={alert.get('source_ip_address')}"
        )


def summarize_evaluations(rows: List[Dict[str, Any]]) -> None:
    print_section("Evaluation Run Summary")

    if not rows:
        print("No evaluation run logs found.")
        return

    latest = rows[-1]

    print(f"Total evaluation runs: {len(rows)}")
    print(f"Latest timestamp: {latest.get('timestamp')}")
    print(f"Latest score: {latest.get('overall_score')}")
    print(f"Passed test cases: {latest.get('passed_test_cases')}/{latest.get('total_test_cases')}")
    print(f"Results path: {latest.get('results_path')}")

    print("\nLatest check scores:")
    for check_name, check_result in latest.get("check_scores", {}).items():
        print(
            f"- {check_name}: "
            f"{check_result.get('passed')}/{check_result.get('total')} "
            f"({check_result.get('score')})"
        )


def summarize_errors(rows: List[Dict[str, Any]]) -> None:
    print_section("Error Summary")

    if not rows:
        print("No error logs found.")
        return

    print(f"Total errors: {len(rows)}")

    print("\nRecent errors:")
    for row in rows[-5:]:
        print(
            f"- {row.get('timestamp')} | "
            f"component={row.get('component')} | "
            f"finding={row.get('finding_id')} | "
            f"error={row.get('error_message')}"
        )


def main():
    investigation_rows = load_jsonl(INVESTIGATION_LOG_PATH)
    evaluation_rows = load_jsonl(EVALUATION_LOG_PATH)
    error_rows = load_jsonl(ERROR_LOG_PATH)

    summarize_investigations(investigation_rows)
    summarize_evaluations(evaluation_rows)
    summarize_errors(error_rows)


if __name__ == "__main__":
    main()