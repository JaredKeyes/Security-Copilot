import json
from pathlib import Path

EVALUATION_LABELS_PATH = Path("data/raw/evaluation_labels.json")
RESULTS_PATH = Path("data/gold/evaluation_results/investigation_evaluation_results.json")

FORBIDDEN_FILES_FOR_LABELS = [
    Path("src/ingestion/build_bronze.py"),
    Path("src/transformations/build_silver.py"),
    Path("src/transformations/build_gold.py"),
    Path("src/retrieval/build_vector_index.py"),
    Path("src/retrieval/query_vector_index.py"),
    Path("src/rag/basic_rag_answer.py"),
    Path("src/agents/investigation_tools.py"),
    Path("src/agents/investigate_alert.py"),
    Path("src/guardrails/security_guardrails.py"),
]

def check_evaluation_labels_exist() -> bool:
    return EVALUATION_LABELS_PATH.exists()

def check_results_exist() -> bool:
    return RESULTS_PATH.exists()

def check_results_shape()  -> bool:
    if not RESULTS_PATH.exists():
        return False

    with open(RESULTS_PATH, "r", encoding="utf-8") as f:
        payload = json.load(f)

    return (
        "summary" in payload
        and "results" in payload
        and isinstance(payload["results"], list)
        and len(payload["results"]) > 0
    )

def check_labels_not_used_outside_evaluation() -> bool:
    forbidden_reference = "evaluation_labels"

    violations = []

    for path in FORBIDDEN_FILES_FOR_LABELS:
        if not path.exists():
            continue

        text = path.read_text(encoding="utf-8")

        if forbidden_reference in text:
            violations.append(str(path))

    if violations:
        print("\nForbidden evaluation label references found:")
        for violation in violations:
            print(f"- {violation}")

    return len(violations) == 0

def print_check(name: str, passed: bool):
    print(f"{name}: {'PASS' if passed else 'FAIL'}")

def main():
    checks = {
        "evaluation_labels_exists": check_evaluation_labels_exist(),
        "evaluation_results_exists": check_results_exist(),
        "evaluation_results_shape_valid": check_results_shape(),
        "labels_not_used_outside_evaluation": check_labels_not_used_outside_evaluation(),
    }

    print("\n" + "=" * 100)
    print("Evaluation Validation")
    print("=" * 100)

    for name, passed in checks.items():
        print_check(name, passed)

    total = len(checks)
    passed = sum(1 for value in checks.values() if value)

    print("\n" + "=" * 100)
    print(f"Evaluation validation score: {passed}/{total}")

if __name__ == "__main__":
    main()