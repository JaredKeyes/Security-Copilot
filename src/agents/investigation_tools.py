from pathlib import Path
from typing import Any, Dict, List, Optional

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import col

from src.retrieval.query_vector_index import retrieve_runbook_context

GOLD_DIR = Path("data/gold")

def get_spark() -> SparkSession:
    return (
        SparkSession.builder
        .appName("security-copilot-agent-tools")
        .master("local[*]")
        .getOrCreate()
    )

def dataframe_to_dicts(df: DataFrame, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Converts a Spark DataFrome into a list of dictionaries.
    """
    return [row.asDict(recursive=True) for row in df.limit(limit).collect()]

def load_gold_tables(spark: SparkSession) -> Dict[str, DataFrame]:
    return {
        "findings": spark.read.parquet(str(GOLD_DIR / "security_findings_enriched")),
        "timeline": spark.read.parquet(str(GOLD_DIR / "alert_timeline")),
        "user_risk": spark.read.parquet(str(GOLD_DIR / "user_risk_summary")),
        "ip_reputation": spark.read.parquet(str(GOLD_DIR / "ip_reputation_summary")),
    }

def lookup_alert(tables: Dict[str, DataFrame], finding_id: str) -> Optional[Dict[str, Any]]:
    """
    Look up a GuardDuty-style finding by finding_id.
    """
    findings = tables["findings"]

    rows = dataframe_to_dicts(
        findings.filter(col("finding_id") == finding_id),
        limit=1,
    )

    return rows[0] if rows else None

def get_user_timeline(
    tables: Dict[str, DataFrame],
    user_name: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    timeline = tables["timeline"]

    result = (
        timeline
        .filter(col("user_name") == user_name)
        .orderBy("event_timestamp")
    )

    return dataframe_to_dicts(result, limit=limit)

def get_ip_timeline(
    tables: Dict[str, DataFrame],
    source_ip_address: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    timeline = tables["timeline"]

    result = (
        timeline
        .filter(col("source_ip_address") == source_ip_address)
        .orderBy("event_timestamp")
    )

    return dataframe_to_dicts(result, limit=limit)

def get_related_events_for_alert(
    tables: Dict[str, DataFrame],
    finding_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    alert = lookup_alert(tables, finding_id)

    if not alert:
        return []

    user_name = alert.get("user_name")
    source_ip_address = alert.get("source_ip_address")

    timeline = tables["timeline"]

    result = (
        timeline
        .filter(
            (col("user_name") == user_name)
            | (col("source_ip_address") == source_ip_address)
        )
        .orderBy("event_timestamp")
    )

    return dataframe_to_dicts(result, limit=limit)

def get_user_risk_summary(
    tables: Dict[str, DataFrame],
    user_name: str,
) -> Optional[Dict[str, Any]]:
    user_risk = tables["user_risk"]

    rows = dataframe_to_dicts(
        user_risk.filter(col("user_name") == user_name),
        limit=1,
    )

    return rows[0] if rows else None

def get_ip_reputation(
    tables: Dict[str, DataFrame],
    source_ip_address: str,
) -> Optional[Dict[str, Any]]:
    ip_reputation = tables["ip_reputation"]

    rows = dataframe_to_dicts(
        ip_reputation.filter(col("source_ip_address") == source_ip_address),
        limit=1,
    )

    return rows[0] if rows else None

def build_runbook_query(alert: Dict[str, Any]) -> str:
    finding_type = alert.get("finding_type", "")
    title = alert.get("title", "")
    description = alert.get("description", "")
    event_name = alert.get("event_name", "")
    mitre_technique = alert.get("mitre_technique", "")
    resource_name = alert.get("resource_name", "")

    return (
        f"{finding_type} {title} {description}"
        f"{event_name} {mitre_technique} {resource_name}"
    )

def retrieve_relevant_runbook(
    query: str,
    top_k: int = 3,
) -> List[Dict[str, Any]]:
    return retrieve_runbook_context(query=query, top_k=top_k)

def build_investigation_context(
    finding_id: str,
    top_k_runbooks: int = 3,
) -> Dict[str, Any]:
    spark = get_spark()
    tables = load_gold_tables(spark)

    try:
        alert = lookup_alert(tables, finding_id)

        if not alert:
            return {
                "finding_id": finding_id,
                "error": "Finding not found",
            }

        user_name = alert.get("user_name")
        source_ip_address = alert.get("source_ip_address")

        user_timeline = get_user_timeline(tables, user_name) if user_name else []
        ip_timeline = get_ip_timeline(tables, source_ip_address) if source_ip_address else []
        related_events = get_related_events_for_alert(tables, finding_id)
        user_risk = get_user_risk_summary(tables, user_name) if user_name else None
        ip_reputation = get_ip_reputation(tables, source_ip_address) if source_ip_address else None

        runbook_query = build_runbook_query(alert)
        runbook_context = retrieve_relevant_runbook(runbook_query, top_k=top_k_runbooks)

        return {
            "finding_id": finding_id,
            "alert": alert,
            "related_events": related_events,
            "user_timeline": user_timeline,
            "ip_timeline": ip_timeline,
            "user_risk_summary": user_risk,
            "ip_reputation_summary": ip_reputation,
            "runbook_query": runbook_query,
            "runbook_context": runbook_context,
        }
    finally:
        spark.stop()