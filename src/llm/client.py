import os
from functools import lru_cache

import anthropic
import boto3

MODEL = "claude-opus-4-8"

@lru_cache(maxsize=1)
def _api_key() -> str:
    arn = os.environ.get("ANTHROPIC_SECRET_ARN")
    if not arn:
        return os.environ["ANTHROPIC_API_KEY"]
    secret = boto3.client("secretsmanager").get_secret_value(SecretId=arn)
    return secret["SecretString"]

@lru_cache(maxsize=1)
def get_client() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=_api_key())