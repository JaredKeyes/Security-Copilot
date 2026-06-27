import json
from pathlib import Path
from typing import Any, Dict, List

from src.evaluation.evaluation_questions import EVALUATION_TEST_CASES
from src.evaluation.llm_judge import judge_report
from src.evaluation.served_artifacts import load_served_artifact
from src.guardrails.security_guardrails import groundedness_score
from src.monitoring.monitoring_logger import log_evaluation_run

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
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for label in labels:
        grouped.setdefault(label.get("scenario_name", "unknown"), []).append(label)
    return grouped


def build_label(grouped: Dict[str, List[Dict[str, Any]]], scenario: str) -> Dict[str, Any]:
    entries = grouped.get(scenario, [])
    return {
        "scenario_name": scenario,
        "attack_stages": [e.get("attack_stage") for e in entries],
        "expected_reasoning": [e.get("expected_reasoning") for e in entries],
    }


def get_retrieved_runbook_files(context: Dict[str, Any]) -> List[str]:
    files = []
    for result in context.get("runbook_context", []):
        file_name = result.get("metadata", {}).get("file_name")
        if file_name:
            files.append(file_name)
    return sorted(set(files))

SCENARIO_KEYWORD_THRESHOLD = 0.6

def scenario_identified(report: str, test_case: Dict[str, Any]) -> bool:
    keywords = test_case.get("expected_pattern_keywords", [])
    if not keywords:
        return False
    lower = report.lower()
    found = sum(1 for kw in keywords if kw.lower() in lower)
    return (found / len(keywords)) >= SCENARIO_KEYWORD_THRESHOLD


def evaluate_test_case(
    test_case: Dict[str, Any], grouped_labels: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    finding_id = test_case["finding_id"]
    expected_scenario = test_case["expected_scenario"]
    expected_runbook = test_case["expected_runbook"]

    artifact = load_served_artifact(finding_id)
    if artifact is None:
        return {
            "finding_id": finding_id,
            "expected_scenario": expected_scenario,
            "passed": False,
            "error": "served artifact not found in S3 (precompute first)",
        }

    report = artifact["report"]
    context = artifact["context"]
    label = build_label(grouped_labels, expected_scenario)

    grounded = groundedness_score(report, context)
    judge = judge_report(report, context, label)
    retrieved = get_retrieved_runbook_files(context)
    expected_runbook_found = expected_runbook in retrieved
    scenario_present = scenario_identified(report, test_case)

    judge_correct = judge["correctness"] >= 4
    meta_eval_agree = judge_correct == scenario_present

    passed = bool(judge["passed"] and expected_runbook_found)

    return {
        "finding_id": finding_id,
        "expected_scenario": expected_scenario,
        "passed": passed,
        "groundedness": grounded,
        "judge": judge,
        "expected_runbook": expected_runbook,
        "retrieved_runbooks": retrieved,
        "expected_runbook_found": expected_runbook_found,
        "scenario_present": scenario_present,
        "meta_eval_agree": meta_eval_agree,
        "model": artifact.get("model"),
        "generated_at": artifact.get("generated_at"),
    }


def compute_meta_eval_agreement(results: List[Dict[str, Any]]) -> float:
    scored = [r for r in results if "judge" in r and "scenario_present" in r]
    if not scored:
        return 0.0
    agree = sum(
        1 for r in scored if (r["judge"]["correctness"] >= 4) == r["scenario_present"]
    )
    return agree / len(scored)


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    passed = sum(1 for r in results if r.get("passed") is True)
    scored = [r for r in results if "groundedness" in r]

    groundedness_mean = (
        sum(r["groundedness"] for r in scored) / len(scored) if scored else 0.0
    )
    judge_pass_rate = (
        sum(1 for r in scored if r["judge"]["passed"]) / len(scored) if scored else 0.0
    )
    meta_eval_agreement = compute_meta_eval_agreement(results)

    return {
        "total_test_cases": total,
        "passed_test_cases": passed,
        "overall_score": passed / total if total else 0,
        "groundedness_mean": groundedness_mean,
        "judge_pass_rate": judge_pass_rate,
        "meta_eval_agreement": meta_eval_agreement,
        "check_scores": {
            "expected_runbook_found": {
                "passed": sum(1 for r in scored if r.get("expected_runbook_found")),
                "total": len(scored),
            },
            "judge_passed": {
                "passed": sum(1 for r in scored if r["judge"]["passed"]),
                "total": len(scored),
            },
        },
    }


def save_results(results: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "results": results}, f, indent=2, default=str)


def main():
    grouped_labels = group_labels_by_scenario(load_evaluation_labels())

    print("\nScoring SERVED artifacts (pre-ship quality gate).")
    print(f"Scenarios in hidden labels: {sorted(grouped_labels.keys())}")

    results = []
    for test_case in EVALUATION_TEST_CASES:
        print("\n" + "=" * 100)
        print(f"Evaluating finding: {test_case['finding_id']}")
        result = evaluate_test_case(test_case, grouped_labels)
        results.append(result)
        print(f"Passed: {result.get('passed')}  groundedness: {result.get('groundedness')}")
        if "judge" in result:
            j = result["judge"]
            print(f"Judge F/C/Comp: {j['faithfulness']}/{j['correctness']}/{j['completeness']} "
                f"pass={j['passed']}  meta_agree={result.get('meta_eval_agree')}")

    summary = summarize_results(results)
    save_results(results, summary)

    log_evaluation_run(
        total_test_cases=summary["total_test_cases"],
        passed_test_cases=summary["passed_test_cases"],
        overall_score=summary["overall_score"],
        check_scores=summary["check_scores"],
        results_path=str(RESULTS_PATH),
        groundedness_mean=summary["groundedness_mean"],
        judge_pass_rate=summary["judge_pass_rate"],
        meta_eval_agreement=summary["meta_eval_agreement"],
    )

    print("\n" + "=" * 100)
    print("Evaluation Summary")
    print(json.dumps(summary, indent=2))
    print(f"\nSaved results to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()