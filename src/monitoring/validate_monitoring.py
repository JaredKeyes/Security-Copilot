from pathlib import Path

from src.monitoring.inspect_monitoring_logs import load_jsonl


MONITORING_DIR = Path("data/gold/monitoring")
INVESTIGATION_LOG_PATH = MONITORING_DIR / "investigation_requests.jsonl"
EVALUATION_LOG_PATH = MONITORING_DIR / "evaluation_runs.jsonl"
ERROR_LOG_PATH = MONITORING_DIR / "errors.jsonl"


def print_check(name: str, passed: bool) -> None:
    print(f"{name}: {'PASS' if passed else 'FAIL'}")


def check_monitoring_dir_exists() -> bool:
    return MONITORING_DIR.exists()


def check_investigation_log_exists() -> bool:
    return INVESTIGATION_LOG_PATH.exists()


def check_investigation_log_shape() -> bool:
    rows = load_jsonl(INVESTIGATION_LOG_PATH)

    if not rows:
        return False

    required_fields = {
        "timestamp",
        "finding_id",
        "status",
        "latency_seconds",
        "guardrail_status",
        "runbook_sources",
        "alert_summary",
    }

    return required_fields.issubset(set(rows[-1].keys()))


def check_evaluation_log_exists() -> bool:
    return EVALUATION_LOG_PATH.exists()


def check_evaluation_log_shape() -> bool:
    rows = load_jsonl(EVALUATION_LOG_PATH)

    if not rows:
        return False

    required_fields = {
        "timestamp",
        "total_test_cases",
        "passed_test_cases",
        "overall_score",
        "check_scores",
        "results_path",
    }

    return required_fields.issubset(set(rows[-1].keys()))


def main():
    checks = {
        "monitoring_dir_exists": check_monitoring_dir_exists(),
        "investigation_log_exists": check_investigation_log_exists(),
        "investigation_log_shape_valid": check_investigation_log_shape(),
        "evaluation_log_exists": check_evaluation_log_exists(),
        "evaluation_log_shape_valid": check_evaluation_log_shape(),
    }

    print("\n" + "=" * 100)
    print("Monitoring Validation")
    print("=" * 100)

    for name, passed in checks.items():
        print_check(name, passed)

    total = len(checks)
    passed = sum(1 for value in checks.values() if value)

    print("\n" + "=" * 100)
    print(f"Monitoring validation score: {passed}/{total}")


if __name__ == "__main__":
    main()