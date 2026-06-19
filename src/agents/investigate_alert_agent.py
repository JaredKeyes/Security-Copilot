import json
import sys
from typing import Any, Dict, List

from src.agents.agent_tools import TOOLS, build_tables, make_dispatch
from src.llm.client import MODEL, get_client

AGENT_SYSTEM = """You are a SOC investigation agent. Given a finding_id, \
investigate by calling tools, then write a grounded markdown report.

- Start by looking up the alert. Then gather only the evidence you need \
(related events, user/IP timelines, risk/reputation, relevant runbooks).
- Gound every claim in tool results. Never invent evidence.
- Flag destructive/containment steps as requiring human approval.
- When you have enough evidence, stop calling tools and write the report with \
sections: Alert Overview, Likely Pattern, Evidence (with citations), \
Recommended Next Steps, Confidence."""

def investigate_with_agent(finding_id: str, max_steps: int = 8) -> Dict[str, Any]:
    client = get_client()
    dispatch = make_dispatch(build_tables())

    messages: List[Dict[str, Any]] = [
        {"role": "user", "content": f"Investigate finding_id={finding_id}."}
    ]
    tool_calls: List[str] = []

    for _ in range(max_steps):
        response = client.messages.create(
            model=MODEL,
            max_tokens=8000,
            thinking={"type": "adaptive"},
            system=AGENT_SYSTEM,
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason != "tool_use":
            report = "".join(b.text for b in response.content if b.type == "text")
            return {"report": report, "tool_calls": tool_calls,
                    "stop_reason": response.stop_reason}

        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            tool_calls.append(block.name)
            try:
                result = dispatch(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result, default=str),
                })
            except Exception as exc:
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": f"Error: {exc}",
                    "is_error": True,
                })
        messages.append({"role": "user", "content": tool_results})

    return {"report": "Investigation incomplete: step budget exhausted.",
            "tool_calls": tool_calls, "stop_reason": "max_steps"}

def main():
    finding_id = sys.argv[1] if len(sys.argv) > 1 else "gd-seeded-0001"
    result = investigate_with_agent(finding_id)
    print("Tool trajectory:", " -> ".join(result["tool_calls"]) or "(none)")
    print("Stop reason:", result["stop_reason"])
    print("=" * 100)
    print(result["report"])

if __name__ == "__main__":
    main()