import json, os
import boto3
from src.guardrails.security_guardrails import groundedness_score

REPORTS_BUCKET = os.environ["REPORTS_BUCKET"]
PREFIX = "reports"

def run() -> None:
    s3 = boto3.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    updated = 0
    for page in paginator.paginate(Bucket=REPORTS_BUCKET, Prefix=f"{PREFIX}/"):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json") or key.endswith("index.json"):
                continue
            record = json.loads(s3.get_object(Bucket=REPORTS_BUCKET, Key=key)["Body"].read())
            if "report" not in record or "context" not in record:
                continue
            record["groundedness"] = groundedness_score(record["report"], record["context"])
            s3.put_object(Bucket=REPORTS_BUCKET, Key=key,
                            Body=json.dumps(record, default=str).encode("utf-8"),
                            ContentType="application/json")
            updated += 1
        print(f"Backfilled groundedness on {updated} records.")

if __name__ == "__main__":
    run()