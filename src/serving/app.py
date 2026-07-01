import json
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

import boto3
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from src.llm.answer_question import answer_question, QuestionRejected
from src.serving import budget
from src.guardrails.security_guardrails import check_citation_coverage

REPORTS_BUCKET = os.environ["REPORTS_BUCKET"]
REPORTS_PREFIX = "reports"

app = FastAPI(title="Security-Copilot Demo API", version="1.0.0")

@app.options("/{full_path:path}")
def preflight(full_path: str) -> Response:
    return Response(status_code=204)

@lru_cache(maxsize=1)
def _s3():
    return boto3.client("s3")

def _get_json(key: str) -> Optional[dict]:
    try:
        obj = _s3().get_object(Bucket=REPORTS_BUCKET, Key=key)
    except _s3().exceptions.NoSuchKey:
        return None
    return json.loads(obj["Body"].read())

@lru_cache(maxsize=64)
def _load_record(finding_id: str) -> Optional[dict]:
    return _get_json(f"{REPORTS_PREFIX}/{finding_id}.json")

class AskRequest(BaseModel):
    finding_id: str
    question: str
    history: List[Dict[str, Any]] = []

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}

@app.get("/alerts")
def list_alerts() -> Dict[str, Any]:
    index = _get_json(f"{REPORTS_PREFIX}/index.json")
    if index is None:
        raise HTTPException(503, "Demo data not available")
    return index

@app.get("/alerts/{finding_id}")
def get_alert(finding_id: str) -> Dict[str, Any]:
    record = _load_record(finding_id)
    if record is None:
        raise HTTPException(404, "Finding not found")
    return {"finding_id": finding_id, "report": record["report"],
            "model": record["model"], "generated_at": record["generated_at"],
            "groundedness": record.get("groundedness")}

@app.post("/ask")
def ask(req: AskRequest) -> Dict[str, Any]:
    record = _load_record(req.finding_id)
    if record is None:
        raise HTTPException(404, "Finding not found")

    if not budget.reserve():
        return {"answer": None, "budget_exceeded": True,
                "fallback_report": record["report"]}

    try:
        answer, used = answer_question(record["context"], req.question, req.history)
    except QuestionRejected as e:
        raise HTTPException(400, str(e))

    coverage = check_citation_coverage(answer, record["context"])
    budget.reconcile(budget.ESTIMATE_TOKENS, used)
    return {"answer": answer, "budget_exceeded": False,
            "remaining_tokens": budget.remaining(),
            "review_required": not coverage["passed"],
            "uncited_entities": coverage["missing_entities"]}

try:
    from mangum import Mangum
    handler = Mangum(app)
except ImportError:
    handler = None