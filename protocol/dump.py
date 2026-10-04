"""The baseline condition's output: an unstructured transcript of the stopped
investigation. The agent's own verdict is removed (the agent "stopped" before
concluding), so the analyst must work from the raw trail.
"""
from __future__ import annotations

import json
from typing import Any, List, Sequence

BANNER = (
    "=== INVESTIGATION STOPPED ===\n"
    "The agent could not complete this triage: required context is missing.\n"
    "Below is everything it gathered. Decide the verdict yourself."
)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            parts.append(p.get("text", "") if isinstance(p, dict) else str(p))
        return "".join(parts)
    return str(content)


def _is_verdict_message(msg: Any, verdict_tool: str) -> bool:
    mtype = getattr(msg, "type", "")
    if mtype == "tool" and getattr(msg, "name", None) == verdict_tool:
        return True
    if mtype == "ai":
        calls = getattr(msg, "tool_calls", None) or []
        if any(c.get("name") == verdict_tool for c in calls):
            return True
        if not calls:
            body = _text(getattr(msg, "content", "")).strip()
            if body.startswith("```"):
                body = body.strip("`").removeprefix("json").strip()
            try:
                data = json.loads(body)
                return isinstance(data, dict) and "recommended_action" in data
            except (ValueError, TypeError):
                return False
    return False


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [truncated {len(text) - limit} chars]"


def format_context_dump(
    messages: Sequence[Any], *, verdict_tool: str = "TriageVerdict", max_chars: int = 1500
) -> str:
    lines: List[str] = [BANNER, ""]
    for msg in messages:
        if _is_verdict_message(msg, verdict_tool):
            continue
        mtype = getattr(msg, "type", "message")
        label = {"human": "user", "ai": "agent"}.get(mtype, mtype)
        if mtype == "tool":
            label = f"tool:{getattr(msg, 'name', '?')}"
        body = _clip(_text(getattr(msg, "content", "")), max_chars)
        calls = getattr(msg, "tool_calls", None) or []
        if calls:
            body += "\n  tool calls: " + "; ".join(f"{c.get('name')}({c.get('args')})" for c in calls)
        if body.strip():
            lines.append(f"[{label}] {body}\n")
    return "\n".join(lines)