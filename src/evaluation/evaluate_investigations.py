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

def group_labels_by_scenario(labels: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
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

    for result in context.get()
