import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


MONITORING_DIR = Path("data/gold/monitoring")
INVESTIGATION_LOG_PATH = MONITORING_DIR / "investigation_requests.jsonl"
EVALUATION_LOG_PATH = MONITORING_DIR / "evaluation_runs.jsonl"
ERROR_LOG_PATH = MONITORING_DIR / "errors.jsonl"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_monitoring_dir() -> None:
    MONITORING_DIR.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    ensure_monitoring_dir()

    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, default=str) + "\n")


def log_investigation_request(
    finding_id: str,
    status: str,
    latency_seconds: float,
    alert: Optional[Dict[str, Any]] = None,
    runbook_sources: Optional[list] = None,
    guardrail_status: Optional[str] = None,
    report_length_chars: Optional[int] = None,
    related_event_count: Optional[int] = None,
    user_timeline_count: Optional[int] = None,
    ip_timeline_count: Optional[int] = None,
    error: Optional[str] = None,
) -> None:
    payload = {
        "timestamp": utc_now_iso(),
        "finding_id": finding_id,
        "status": status,
        "latency_seconds": latency_seconds,
        "guardrail_status": guardrail_status,
        "report_length_chars": report_length_chars,
        "related_event_count": related_event_count,
        "user_timeline_count": user_timeline_count,
        "ip_timeline_count": ip_timeline_count,
        "runbook_sources": runbook_sources or [],
        "alert_summary": {
            "finding_type": alert.get("finding_type") if alert else None,
            "severity": alert.get("severity") if alert else None,
            "severity_label": alert.get("severity_label") if alert else None,
            "user_name": alert.get("user_name") if alert else None,
            "source_ip_address": alert.get("source_ip_address") if alert else None,
            "resource_name": alert.get("resource_name") if alert else None,
            "event_name": alert.get("event_name") if alert else None,
            "risk_level": alert.get("risk_level") if alert else None,
            "is_known_bad_ip": alert.get("is_known_bad_ip") if alert else None,
        },
        "error": error,
    }

    append_jsonl(INVESTIGATION_LOG_PATH, payload)


def log_evaluation_run(
    total_test_cases: int,
    passed_test_cases: int,
    overall_score: float,
    check_scores: Dict[str, Any],
    results_path: str,
    groundedness_mean: Optional[float] = None,
    judge_pass_rate: Optional[float] = None,
    meta_eval_agreement: Optional[float] = None,
) -> None:
    payload = {
        "timestamp": utc_now_iso(),
        "total_test_cases": total_test_cases,
        "passed_test_cases": passed_test_cases,
        "overall_score": overall_score,
        "check_scores": check_scores,
        "results_path": results_path,
        "groundedness_mean": groundedness_mean,
        "judge_pass_rate": judge_pass_rate,
        "meta_eval_agreement": meta_eval_agreement,
    }

    append_jsonl(EVALUATION_LOG_PATH, payload)


def log_error(
    component: str,
    error_message: str,
    finding_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "timestamp": utc_now_iso(),
        "component": component,
        "finding_id": finding_id,
        "error_message": error_message,
        "extra": extra or {},
    }

    append_jsonl(ERROR_LOG_PATH, payload)


class Timer:
    def __init__(self):
        self.start_time = time.perf_counter()

    def elapsed(self) -> float:
        return round(time.perf_counter() - self.start_time, 4)