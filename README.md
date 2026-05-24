# Enterprise Security GenAI Copilot

## Overview

This project builds a production-style GenAI security investigation assistant using lakehouse architecture, RAG, tool-calling agents, guardrails, evaluation, observability, and MLOps.

The goal is to simulate how an enterprise security team could use AI to accelerate alert triage and incident investigation.

## Milestone 1: Basic Data Platform

This milestone creates a lakehouse-style data foundation for security analytics.

### Data Sources

- Synthetic AWS CloudTrail events
- Synthetic GuardDuty findings
- IAM user metadata
- Threat intelligence indicators

### Lakehouse Layers

#### Bronze

Raw ingested data stored as Parquet.

#### Silver

Cleaned and normalized security data.

#### Gold

Analyst-ready tables for investigation workflows.

### Gold Tables

| Table | Purpose |
|---|---|
| security_findings_enriched | GuardDuty findings joined with related CloudTrail context |
| user_risk_summary | User-level risk scoring |
| ip_reputation_summary | IP-level activity and threat intelligence summary |
| alert_timeline | Timeline of security-relevant cloud activity | 

## Run Locally

```bash
python -m src.ingestion.generate_synthetic_data
python -m src.ingestion.build_bronze
python -m src.transformations.build_silver
python -m src.transformations.build_gold
python -m src.queries.basic_investigation_queries