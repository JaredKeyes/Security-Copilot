import json
import os
from functools import lru_cache
from typing import Any, Dict, Optional

import boto3

REPORTS_PREFIX = "reports"

@lru_cache(maxsize=1)
def _s3():
    return boto3.client("s3")

def _bucket() -> str:
    bucket = os.environ.get("REPORTS_BUCKET")
    if not bucket:
        raise RuntimeError(
            "REPORTS_BUCKET not set; cannot load served artifacts. "
            "Set it and use AWS profile 'test' for the demo account."
        )
    return bucket

def load_served_artifact(finding_id: str) -> Optional[Dict[str, Any]]:
    try:
        obj = _s3().get_object(
            Bucket=_bucket(), Key=f"{REPORTS_PREFIX}/{finding_id}.json"
        )
    except _s3().exceptions.NoSuchKey:
        return None
    return json.loads(obj["Body"].read())