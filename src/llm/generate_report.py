import json
from typing import Any, Dict

from src.llm.client import MODEL, get_client

SYSTEM_PROMPT = """You are a SOC investigation assitant. You write grounded \
incident investigation summaries for security analysts.

Rules:
- Use ONLY the evidence in the provided investigation context. Never invent \
findings, IPs, users, timestamps, or MITRE techniques that are not present.
- When you state a fact, attribute it to its source (the alert, a timeline \
event, the user/IP summaries, or a runbook chunk by file_name + chunnk_index).
- If the evidence is insufficient to support a conclusion, say so explicitly \
rather than guessing.
- Recommend next steps, but flag any destructive/containment action as \
requiring human approval.

Output a markdown report with these sections: Alert Overview, Likely Pattern, \
Evidence Summary (with citations), Related Timeline, Recommended Next Steps, \
Confidence (High/Medium/Low with one-line justification)."""

def generate_report_llm(context: Dict[str, Any]) -> str:
    """Grounded narrative report from the (already-retrieved) context dict."""
    client = get_client()

    grounding = json.dumps(context, indent=2, sort_keys=True, default=str)

    with client.messages.stream(
        model=MODEL,
        max_tokens=8000,
        thinking={"type": "adaptive"},
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[
            {
                "role": "user",
                "content": (
                    "Investigation context (JSON), Write the report grounded "
                    "strictly in this evidence:\n\n" + grounding
                ),
            }
        ],
    ) as stream:
        message = stream.get_final_message()

    return "".join(b.text for b in message.content if b.type == "text")