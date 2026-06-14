from Pathlib import Path
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

@app.get("/alerts")
def list_alerts(limit: int = 25) -> Dict[str, Any]:
    spark = get_spark()

    try:
        tables = load_gold_tables(spark)
        findings = tables["findings"]

        result = (
            findings
            .select(
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
            )
            .orderBy(col("severity").desc(), col("finding_timestamp").desc())
        )

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
        raise
