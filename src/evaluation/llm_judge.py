import json
from typing import Any, Dict

from src.llm.client import get_client

JUDGE_MODEL = "claude-sonnet-4-6"
JUDGE_MAX_TOKENS = 1500

JUDGE_SYSTEM = (
    "You are an impartial evaluator of SOC investigation reports. You did NOT "
    "write the report. Grade it ONLY against the provided evidence context and "
    "the hidden ground-truth label. Be strict about faithfulness: any claim not "
    "supported by the context counts against it. Always call the submit_evaluation tool."
)

RUBRIC = (
    "Score three dimensions, integers 1-5:\n"
    "- faithfulness: claims supported by the context, nothing invented."
    "5=every claim grounded; 1=major fabrications.\n"
    "- correctness: does the report identify the labeled scenario/pattern? "
    "5=exactly the labeled scenario; 1=wrong scenario.\n"
    "- completeness: does it cover the key evidence/events?"
    "5=all key events; 1=misses most. (Advisory only.)\n"
)

JUDGE_TOOL = {
    "name": "submit_evaluation",
    "description": "Submit the structured evaluation scores and rationales.",
    "input_schema": {
        "type": "object",
        "properties": {
            "faithfulness": {"type": "integer", "minimum": 1, "maximmum": 5},
            "faithfulness_rationale": {"type": "string"},
            "correctness": {"type": "integer", "minimum": 1, "maximum": 5},
            "correctness_rationale": {"type": "string"},
            "completeness": {"type": "integer", "minimum": 1, "maximum": 5},
            "completeness_rationale": {"type": "string"},
        },
        "required": [
            "faithfulness", "faithfulness_rationale",
            "correctness", "correctness_rationale",
            "completeness", "completeness_rationale",
        ],
    },
}

def judge_passed(scores: Dict[str, Any]) -> bool:
    return scores["faithfulness"] >= 4 and scores["correctness"] >= 4

def judge_report(
    report: str, context: Dict[str, Any], label: Dict[str, Any]
) -> Dict[str, Any]:
    client = get_client()
    grounding = json.dumps(context, sort_keys=True, default=str)
    label_text = json.dumps(label, default=str)

    user_content = (
        RUBRIC
        + "\n\nEVIDENSE CONTEXT (JSON):\n" + grounding
        + "\n\nHIDDEN GROUND-TRUTH LABEL:\n" + label_text
        + "\n\nREPORT TO EVALUATE:\n" +  report
    )

    resp =client.messages.create(
        model=JUDGE_MODEL,
        max_tokens=JUDGE_MAX_TOKENS,
        system=JUDGE_SYSTEM,
        tools=[JUDGE_TOOL],
        tool_choice={"type": "tool", "name": "submit_evaluation"},
        messages=[{"role": "user", "content": user_content}],
    )

    block = next(b for b in resp.content if b.type == "tool_use")
    scores = dict(block.input)
    scores["passed"] = judge_passed(scores)
    return scores