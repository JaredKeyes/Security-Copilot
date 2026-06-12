import json
from pathlib import Path
from typing import Any, Dict, List

from src.agents.investigate_alert import generate_investigation_report
from src.agents.investigation_tools import build_investigation_context
from src.evaluation_questions import EVALUATION_TEST_CASES

EVALUATION_LABELS_PATH = Path("data/raw/evaluation_labels.json")
RESULTS_DIR = Path("data/gold/evaluation_results")
RESULTS_PATH = RESULTS_DIR / "investigation_evaluation_results.json"


def load_evaluation_labels() -> List[Dict[str, Any]]:
    if not EVALUATION_LABELS_PATH.exists():
        raise FileNotFoundError(
            f"Could not find {EVALUATION_LABELS_PATH}. "
            "Run python -m src.ingestion.generate_synthetic_data first."
        )

    with open(EVALUATION_LABELS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def group_labels_by_scenario(
    labels: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    grouped = {}

    for label in labels:
        scenario_name = label.get("scenario_name", "unknown")
        grouped.setdefault(scenario_name, []).append(label)

    return grouped


def text_contains_all_terms(text: str, terms: List[str]) -> Dict[str, Any]:
    lower_text = text.lower()

    found = []
    missing = []

    for term in terms:
        if term.lower() in lower_text:
            found.append(term)
        else:
            missing.append(term)

    return {
        "found": found,
        "missing": missing,
        "score": len(found) / len(terms) if terms else 1.0,
    }


def get_retrieved_runbook_files(context: Dict[str, Any]) -> List[str]:
    files = []

    for result in context.get("runbook_context", []):
        metadata = result.get("metadata", {})
        file_name = metatdata.get("file_name")

        if file_name:
            files.append(file_name)

    return sorted(set(files))


def extract_guardrail_status(report: str) -> str:
    if "## Guardrail Check" not in report:
        return "MISSING"

    if "Status: PASS" in report:
        return "PASS"

    if "Status: REVIEW_REQUIRED" in report:
        return "REVIEW_REQUIRED"

    return "UNKNOWN"


def evaluate_test_case(test_case: Dict[str, Any]) -> Dict[str, Any]:
    finding_id = test_case["finding_id"]

    context = build_investigation_context(finding_id)
    report = generate_investigation_report(finding_id)

    if "error" in context:
        return {
            "finding_id": finding_id,
            "passed": False,
            "error": context["error"],
        }

    expected_keywords = test_case["expected_pattern_keywords"]
    expected_events = test_case["expected_event_names"]
    expected_runbook = test_case["expected_runbook"]
    expected_scenario = test_case["expected_scenario"]

    keyword_result = text_contains_all_terms(report, expected_keywords)
    event_result = text_contains_all_terms(report, expected_events)

    retrieved_runbooks = get_retrieved_runbook_files(context)
    expected_runbook_found = expected_runbook in retrieved_runbooks

    report_generated = "Investigation Report" in report
    guardrail_status = extract_guardrail_status(report)
    guardrail_present = guardrail_status in {"PASS", "REVIEW_REQUIRED"}

    likely_pattern_mentions_scenario = (
        expected_scenario.replace("_", " ") in report.lower()
    )

    checks = {
        "report_generated": report_generated,
        "expected_runbook_found": expected_runbook_found,
        "guardrail_present": guardrail_present,
        "keyword_coverage_passed": keyword_result["score"] >= 0.6,
        "event_coverage_passed": event_result["score"] >= 0.8,
        "scenario_language_present": likely_pattern_mentions_scenario,
    }

    passed = all(checks.values())

    return {
        "finding_id": finding_id,
        "expected_scenario": expected_scenario,
        "passed": passed,
        "checks": checks,
        "keyword_result": keyword_result,
        "event_result": event_result,
        "expected_runbook": expected_runbook,
        "retrieved_runbooks": retrieved_runbooks,
        "guardrail_status": guardrail_status,
    }


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    passed = sum(1 for result in results if result.get("passed") is True)

    checks_totals = {}
    checks_passes = {}

    for result in results:
        for check_name, check_value in result.get("checks", {}).items():
            check_totals[check_name] = check_totals.get(check_name, 0) + 1
