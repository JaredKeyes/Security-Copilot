import os
from typing import Any, Dict, List

import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

st.set_page_config(
    page_title="Enterprise Security GenAI Copilot",
    page_icon="🛡️",
    layout="wide",
)


def api_get(path: str) -> Dict[str, Any]:
    response = requests.get(f"{API_BASE_URL}{path}", timeout=120)
    response.raise_for_status()
    return response.json()


def api_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(f"{API_BASE_URL}{path}", json=payload, timeout=180)
    response.raise_for_status()
    return response.json()


def format_alert_option(alert: Dict[str, Any]) -> str:
    return (
        f"{alert.get('finding_id')} | "
        f"{alert.get('severity_label')} | "
        f"{alert.get('user_name')} | "
        f"{alert.get('event_name')} | "
        f"{alert.get('source_ip_address')}"
    )


def load_alert() -> List[Dict[str, Any]]:
    data = api_get("/alerts?limit=50")
    return data.get("alerts", [])


def show_alert_details(alert: Dict[str, Any]) -> None:
    st.subheader("Selected Alert")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Finding ID", alert.get(finding_id))
    col2.metric("severity", str(alert.get("severity")))
    col3.metric("Severity Label", alert.get("severity_label"))
    col4.metric("Risk Level", alert.get("risk_level"))

    st.write(
        {
            "finding_type": alert.get("finding_type"),
            "title": alert.get("title"),
            "user_name": alert.get("user_name"),
            "source_ip_address": alert.get("source_ip_address"),
            "resource_name": alert.get("resource_name"),
            "event_name": alert.get("event_name"),
            "is_known_bad_ip": alert.get("is_known_bad_ip"),
            "finding_timestamp": alert.get("finding_timestamp"),
        }
    )


def show_monitoring_summary() -> None:
    st.subheader("Monitoring Summary")

    try:
        summary = api_get("/monitoring/summary")
    except Exception as exc:
        st.error(f"Could not load monitoring summery: {exc}")
        return

    investigations = summary.get("investigations", {})
    evaluations = summary.get("evaluations", {})
    errors = summary.get("errors", {})

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Investigations", investigations.get("total", 0))
    col2.metric("Successful", investigations.get("successful", 0))
    col3.metric("Failed", investigations.get("failed", 0))
    col4.metric("Avg Latency", investigations.get("average_latency_seconds", 0))

    st.write("Guardrail Status Counts")
    st.write(investigations.get("guardrail_status_counts", {}))

    latest_eval = evaluations.get("latest")

    if latest_eval:
        st.write("Latest Evaluation Run")

        col1, col2, col3 = st.columns(3)

        col1.metric("Overall Score", latest_eval.get("overall_score"))
        col2.metric("Passed Test Cases", latest_eval.get("passed_test_cases"))
        col3.metric("Total Test Cases", latest_eval.get("total_test_cases"))

        with st.expander("Evaluation Check Scores"):
            st.json(latest_eval.get("check_scores", {}))

    else:
        st.info("No evaluation runs logged yet.")

    with st.expander("Recent Investigation Logs"):
        st.json(investigations.get("recent", []))

    with st.expander("Recent Errors"):
        st.json(error.get("recent", []))


def main():
    st.title("🛡️ Enterprise Security GenAI Copilot")
    st.caption(
        "Lakehouse security data + RAG runbooks + investigation workflow + guardrails + evaluation + monitoring"
    )

    try:
        health = api_get("/heath")
        st.success(f"API status: {health.get('status')}")
    except Exception as exc:
        st.error(
            f"Could not reach API at {API_BASE_URL}. "
            f"Start the API with: uvicorn src.api.main:app --reload"
        )
        st.exception(exc)
        return

    tab1, tab2, tab3 = st.tabs(
        [
            "Investigate Alert",
            "Alert Context",
            "Monitoring",
        ]
    )

    with tab1:
        st.header("Investigate Alert")

        try:
            alerts = load_alerts()
        except Exception as exc:
            st.error(f"Could not load alerts: {exc}")
            return

        if not alerts:
            st.warning("No alerts found. Run the Milestone 1 pipeline first.")
            return

        selected_label = st.selectbox(
            "Choose a finding",
            options=[format_alert_option(alert) for alert in alerts],
        )

        selected_index = [format_alert_option(alert) for alert in alerts].index(
            selected_label
        )
        selected_alert = alerts[selected_index]
