# Enterprise Security GenAI Copilot

## Overview

This project builds a production-style GenAI security investigation assistant using lakehouse architecture, RAG, tool-calling agents, guardrails, evaluation, observability, and MLOps.

The goal is to simulate how an enterprise security team could use AI to accelerate alert triage and incident investigation.

## Milestone 1: Lakehouse Security Data Platform

### What this milestone does

- Generates synthetic cloud security data
- Plants realistic attack chains into noisy background activity
- Keeps ground-truth evaluation labels separate from model-accessible logs
- Builds bronze, silver, and gold lakehouse-style layers
- Produces analyst-ready security investigation tables

### Important design choice

The project intentionally separates investigation data from evaluation labels.

The AI assistant will be allowed to use:

- CloudTrail-style events
- GuardDuty-style findings
- IAM metadata
- Threat intelligence
- Enriched gold tables

The AI assistant will not be allowed to use:

- `evaluation_labels.json`

That file acts as the hidden answer key for later evaluation.

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


## Milestone 2: RAG Knowledge Base

This milestone adds a retrieval-augmented generation knowledge layer over security runbooks.

### What it does

- Creates Markdown runbooks for common cloud security investigation scenarios
- Chunks runbook documents into retrievable sections
- Generates local embeddings using Sentence Transformers
- Stores embeddings in a local Chroma vector database
- Retrieves relevant runbook context for analyst questions
- Returns source metadata for traceability

### Run Milestone 2

```bash
python -m src.retrieval.build_vector_index
python -m src.retrieval.query_vector_index
python -m src.retrieval.validate_retrieval
python -m src.rag.basic_rag_answer