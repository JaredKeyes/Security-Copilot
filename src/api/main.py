from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pyspark.sql.functions import col

from src.agents.investigate_alert import generate_investigation_report
from src.agents.investigation_tools import (
    build_investigation_context,
    dataframe_to_dicts,
    get_spark,
    load_gold_tables,
)
from src.monitoring.inspect_monitoring_logs import load_jsonl
from src.monitoring.monitoring_logger import (
    EVALUATION_LOG_PATH,
    ERROR_LOG_PATH,
    INVESTIGATION_LOG_PATH,
)

app = FastAPI(
    title="Enterprise Security GenAI Copilot API",
    description="API for investigating synthetic cloud security findings using lakehouse data, RAG, guardrails, evaluation, and monitoring.",
    version="0.1.0",
)


class InvestigationRequest(BaseModel):
    finding_id: str


class InvestigationResponse(BaseModel):
    finding_id: str
    report: str


@app.get("/health")
def health_check() -> Dict[str, str]:
    return {
        "status": "ok",
        "service": "enterprise-security-genai-copilot-api",
    }


@app.get("/alerts")
def list_alerts(limit: int = 25) -> Dict[str, Any]:
    spark = get_spark()

    try:
        tables = load_gold_tables(spark)
        findings = tables["findings"]

        result = findings.select(
            "finding_id",
            "finding_timestamp",
            "severity",
            "severity_label",
            "finding_type",
            "title",
            "user_name",
            "source_ip_address",
            "resource_name",
            "event_name",
            "risk_level",
            "is_known_bad_ip",
        ).orderBy(col("severity").desc(), col("finding_timestamp").desc())

        alerts = dataframe_to_dicts(result, limit=limit)

        return {
            "count": len(alerts),
            "alerts": alerts,
        }

    finally:
        spark.stop()


@app.get("/alerts/{finding_id}")
def get_alert_context(finding_id: str) -> Dict[str, Any]:
    context = build_investigation_context(finding_id)

    if "error" in context:
        raise HTTPException(status_code=404, detail=context["error"])

    return context


@app.post("/investigate", response_model=InvestigationResponse)
def investigate_alert(request: InvestigationRequest) -> InvestigationResponse:
    report = generate_investigation_report(request.finding_id)

    if report.startswith("Investigation failed"):
        raise HTTPException(status_code=404, detail=report)

    return InvestigationResponse(
        finding_id=request.finding_id,
        report=report,
    )


@app.get("/monitoring/summary")
def monitoring_summary() -> Dict[str, Any]:
    investigation_rows = load_jsonl(INVESTIGATION_LOG_PATH)
    evaluation_rows = load_jsonl(EVALUATION_LOG_PATH)
    error_rows = load_jsonl(ERROR_LOG_PATH)

    total_investigations = len(investigation_rows)
    successful_investigations = sum(
        1 for row in investigation_rows if row.get("status") == "success"
    )
    failed_investigations = total_investigations - successful_investigations

    latencies = [
        row.get("latency_seconds")
        for row in investigation_rows
        if isinstance(row.get("latency_seconds"), (int, float))
    ]

    avg_latency = round(sum(latencies) / len(latencies), 4) if latencies else 0

    guardrail_status_counts = {}

    for row in investigation_rows:
        status = row.get("guardrail_status", "UNKNOWN")
        guardrail_status_counts[status] = guardrail_status_counts.get(status, 0) + 1

    latest_evaluation: Optional[Dict[str, Any]] = (
        evaluation_rows[-1] if evaluation_rows else None
    )

    return {
        "investigations": {
            "total": total_investigations,
            "successful": successful_investigations,
            "failed": failed_investigations,
            "average_latency_seconds": avg_latency,
            "guardrail_status_counts": guardrail_status_counts,
            "recent": investigation_rows[-5:],
        },
        "evaluations": {
            "total_runs": len(evaluation_rows),
            "latest": latest_evaluation,
        },
        "errors": {"total": len(error_rows), "recent": error_rows[-5:]},
    }
