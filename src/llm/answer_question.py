import json
from typing import Any, Dict, List

from src.llm.client import get_client
from src.guardrails.security_guardrails import check_citation_coverage, mask_secrets

ASK_MODEL = "claude-haiku-4-5"

ASK_SYSTEM = """You are a SOC assistant answering analyst questions about ONE \
specific security finding. Answer ONLY from the provided investigation context \
and runbook excerpts. If the answer isn't there, say you don't have that \
information. Politely decline questions unrelated to this security \
investigation. Be concise"""

MAX_ANSWER_TOKENS = 800
MAX_QUESTION_CHARS = 1000
MAX_TURNS = 8

class QuestionRejected(Exception):
    """Input failed a cap check (too long / too many turns)."""

ANSWER_REVIEW_CAVEAT = (
    "\n\n> REVIEW_REQUIRED: some details above could not be matched to "
    "the investigation evidence and may be inaccurate."
)

def apply_answer_guardrails(answer: str, context: Dict[str, Any]) -> str:
    masked = mask_secrets(answer)
    coverage = check_citation_coverage(masked, context)
    if not coverage["passed"]:
        masked += ANSWER_REVIEW_CAVEAT
    return masked

def answer_question(
    context: Dict[str, Any],
    question: str,
    history: List[Dict[str, Any]] | None = None,
) -> str:
    history = history or []
    if len(question) > MAX_QUESTION_CHARS:
        raise QuestionRejected("Question too long for the demo - please shorten it.")
    if len(history) > 2 * MAX_TURNS:
        raise QuestionRejected("This demo conversation has reached its limit.")

    client = get_client()
    grounding = json.dumps(context, sort_keys=True, default=str)
    from src.retrieval.query_vector_index import retrieve_runbook_context
    runbooks = retrieve_runbook_context(question, top_k=3)

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Investigation context (JSON):\n" + grounding +
                        "\n\nRelevant runbook excerpts:\n" +
                        json.dumps(runbooks, default=str)
                    ),
                    "cache_control": {"type": "ephemeral"},
                }
            ],
        },
        *history,
        {"role": "user", "content": question},
    ]

    resp = client.messages.create(
        model=ASK_MODEL,
        max_tokens=MAX_ANSWER_TOKENS,
        system=[{"type": "text", "text": ASK_SYSTEM, "cache_control": {"type": "ephemeral"}}],
        messages=messages,
    )
    text = next((b.text for b in resp.content if b.type == "text"), "")
    text = apply_answer_guardrails(text, context)
    used = resp.usage.input_tokens + resp.usage.output_tokens
    return text, used