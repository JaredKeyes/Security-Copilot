import datetime as dt
import os

import boto3
from botocore.exceptions import ClientError

BUDGET_TABLE = os.environ.get("BUDGET_TABLE", "demo-budget")
DAILY_TOKEN_CAP = int(os.environ.get("DAILY_TOKEN_CAP", "2000000"))
ESTIMATE_TOKENS = int(os.environ.get("ASK_ESTIMATE_TOKENS", "5000"))

_ddb = boto3.client("dynamodb")

def _today() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()

def reserve(tokens: int = ESTIMATE_TOKENS) -> bool:
    try:
        _ddb.update_item(
            TableName=BUDGET_TABLE,
            Key={"day": {"S": _today()}},
            UpdateExpression="ADD tokens :t",
            ConditionExpression="attribute_not_exists(tokens) OR tokens <= :ceiling",
            ExpressionAttributeValues={
                ":t": {"N": str(tokens)},
                ":ceiling": {"N": str(DAILY_TOKEN_CAP - tokens)},
            },
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise

def reconcile(estimated: int, actual: int) -> None:
    delta = actual - estimated
    if delta == 0:
        return
    _ddb.update_item(
        TableName=BUDGET_TABLE,
        Key={"day": {"S": _today()}},
        UpdateExpression="Add tokens :d",
        ExpressionAttributeValues={":d": {"N": str(delta)}},
    )

def remaining() -> int:
    resp = _ddb.get_item(
        TableName=BUDGET_TABLE,
        Key={"day": {"S": _today()}},
        ConsistentRead=True,
    )
    used = int(resp.get("Item", {}).get("tokens", {}).get("N", "0"))
    return max(DAILY_TOKEN_CAP - used, 0)