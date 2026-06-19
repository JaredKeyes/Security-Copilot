from functools import lru_cache

import anthropic

MODEL = "claude-opus-4-8"

@lru_cache(maxsize=1)
def get_client() -> anthropic.Anthropic:
    return anthropic.Anthropic()