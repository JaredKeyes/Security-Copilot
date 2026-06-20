import datetime as dt
import json
import os
import time

import boto3
from pyspark.sql.functions import col
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request

from src.agents.investigation_tools import build_investigation_context, get_spark, load_gold_tables
from src.llm.client import MODEL, get_client
from src.llm.generate_report import SYSTEM_PROMPT

REPORTS_BUCKET = os.environ["REPORTS_BUCKET"]
REPORTS_PREFIX = "reports"
PRECOMPUTE_MODEL = os.environ.get("PRECOMPUTE_MODEL", MODEL)
MAX_FINDINGS = int(os.environ.get("MAX_FINDINGS", "30"))

INDEX_FIELDS = [
    "finding_id", "finding_timestamp", "severity", "severity_labels",
    "finding_type", "title", "user_name", "source_ip_address",
    "resource_name", "event_name", "risk_level", "is_known_bad_ip",
]

def finding_ids_to_precompute(limit: int) -> list:
    tables = load_gold_tables(get_spark())
    rows = (
        tables["findings"].select("finding_id")
        .orderBy(col("severity").desc())
        .limit(limit)
        .collect()
    )
    return [r["finding_id"] for r in rows]

def build_requests(finding_ids: list):
    requests, contexts = [], {}
    for fid in finding_ids:
        ctx = build_investigation_context(fid)
        if "error" in ctx:
            print(f" skip {fid}: {ctx['error']}")
            continue
        contexts[fid] = ctx
        grounding = json.dumps(ctx, indent=2, sort_keys=True, default=str)
        requests.append(Request(
            custom_id=fid,
            params=MessageCreateParamsNonStreaming(
                model=PRECOMPUTE_MODEL,
                max_tokens=8000,
                thinking={"type": "adaptive"},
                system=[{"type": "text", "text": SYSTEM_PROMPT}],
                messages=[{
                    "role": "user",
                    "content":  "Investigation context (JSON). Write the report "
                                "grounded strictly in this evidence:\n\n" + grounding,
                }],
            ),
        ))
    return requests, contexts

def run() -> None:
    client = get_client()
    s3 = boto3.client("s3")
    now = dt.datetime.now(dt.timezone.utc).isoformat()

    finding_ids = finding_ids_to_precompute(MAX_FINDINGS)
    print(f"Precomputing up to {len(finding_ids)} findings on {PRECOMPUTE_MODEL}...")

    requests, contexts = build_requests(finding_ids)
    if not requests:
        print("No requests to submit.")
        return

    batch = client.messages.batches.create(requests=requests)
    print(f"Batch {batch.id} submitted ({len(requests)} requests). Polling...")
    while True:
        b = client.messages.batches.retrieve(batch.id)
        if b.processing_status == "ended":
            break
        print(f" status={b.processing_status} ...")
        time.sleep(30)

    written = []
    for result in client.messages.batches.results(batch.id):
        fid = result.custom_id
        if result.result.type != "succeeded":
            print(f" {fid}: {result.result.type}")
            continue
        msg = result.result.message
        report = "".join(blk.text for blk in msg.content if blk.type == "text")
        s3.put_object(
            Bucket=REPORTS_BUCKET,
            Key=f"{REPORTS_PREFIX}/{fid}.json",
            Body=json.dumps({
                "finding_id": fid,
                "report": report,
                "context": contexts[fid],
                "model": msg.model,
                "generated_at": now,
            }, default=str).encode("utf-8"),
            ContentType="application/json",
        )
        written.append(fid)

    index = [
        {f: contexts[fid]["alert"].get(f) for f in INDEX_FIELDS}
        for fid in written
    ]
    index.sort(key=lambda r: (r.get("severity") or 0), reverse=True)
    s3.put_object(
        Bucket=REPORTS_BUCKET,
        Key=f"{REPORTS_PREFIX}/index.json",
        Body=json.dumps({"count": len(index), "alerts": index}, default=str).encode("utf-8"),
        ContentType="application/json",
    )

    print(f"Done. Wrote {len(written)} reports + index.json to "
            f"s3://{REPORTS_BUCKET}/{REPORTS_PREFIX}/")

if __name__ == "__main__":
    run()