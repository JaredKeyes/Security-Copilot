from typing import Any, Dict

from src.agents.investigation_tools import (
    get_ip_reputation,
    get_ip_timeline,
    get_related_events_for_alert,
    get_spark,
    get_user_risk_summary,
    get_user_timeline,
    load_gold_tables,
    lookup_alert,
    retrieve_relevant_runbook,
)

TOOLS = [
    {
        "name": "lookup_alert",
        "description": "Look up a GuardDuty-style finding by finding_id. Call "
                        "first to anchor the investigation.",
        "input_schema": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        },
    },
    {
        "name": "get_related_events_for_alert",
        "description": "Timeline of events sharing the alert's user or source IP. "
                        "Call when you need the surrounding activity for a finding.",
        "input_schema": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        },
    },
    {
        "name": "get_user_timeline",
        "description": "Recent activity for a specific user_name.",
        "input_schema": {
            "type": "object",
            "properties": {"user_name": {"type": "string"}},
            "required": ["user_name"],
        },
    },
    {
        "name": "get_ip_timeline",
        "description": "Recent activity for a specific source IP address.",
        "input_schema": {
            "type": "object",
            "properties": {"source_ip_address": {"type": "string"}},
            "required": ["source_ip_address"],
        },
    },
    {
        "name": "get_user_risk_summary",
        "description": "Risk scoring summary for a user_name.",
        "input_schema": {
            "type": "object",
            "properties": {"user_name": {"type": "string"}},
            "required": ["user_name"],
        },
    },
    {
        "name": "get_ip_reputation",
        "description": "Threat-intel / reputation summary for a source IP.",
        "input_schema": {
            "type": "object",
            "properties": {"source_ip_address": {"type": "string"}},
            "required": ["source_ip_address"],
        },
    },
    {
        "name": "retrieve_runbook",
        "description": "Vector search over security runbooks. Call when you need "
                        "investigation or containment guidance for the observed pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "top_k": {"type": "integer"},
            },
            "required": ["query"],
        },
    },
]

def build_tables() -> Dict[str, Any]:
    return load_gold_tables(get_spark())

def make_dispatch(tables: Dict[str, Any]):

    def dispatch(name: str, args: Dict[str, Any]) -> Any:
        if name == "lookup_alert":
            return lookup_alert(tables, args["finding_id"])
        if name == "get_related_events_for_alert":
            return get_related_events_for_alert(tables, args["finding_id"])
        if name == "get_user_timeline":
            return get_user_timeline(tables, args["user_name"])
        if name == "get_ip_timeline":
            return get_ip_timeline(tables, args["source_ip_address"])
        if name == "get_user_risk_summary":
            return get_user_risk_summary(tables, args["user_name"])
        if name == "get_ip_reputation":
            return get_ip_reputation(tables, args["source_ip_address"])
        if name == "retrieve_runbook":
            return retrieve_relevant_runbook(args["query"], top_k=args.get("top_k", 3))
        raise ValueError(f"Unknown tool: {name}")
    
    return dispatch
