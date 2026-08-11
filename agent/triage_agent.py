"""
triage_agent.py — the ReAct triage loop.

Deliberately has NO escalation/interrupt logic — this spike is just about
learning what an automated investigation looks like. Uses the current
(2026) langchain API: `langchain.agents.create_agent`, NOT the deprecated
`langgraph.prebuilt.create_react_agent` (that path is removed in LangGraph
V2.0; verified against the actually-installed package version, not memory).
"""
import json
import os
from pathlib import Path

from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, Field

from logging_callback import TriageLoggingCallback
from tools import ALL_TOOLS

# Free-tier model names change often — if this 404s, run
# `python agent/list_models.py` to see what your key can actually use.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")

ROOT = Path(__file__).resolve().parent.parent
LLM_LOG_DIR = ROOT / "results" / "llm"

SYSTEM_PROMPT = """You are a vulnerability triage analyst investigating a single \
dependency alert in a Java/Maven project.

The dependency's build context (direct/transitive, scope) and the full \
advisory detail (CWE, CVSS, summary, references) are already given to you in \
the first message — that's real, already-fetched data, not something to \
re-derive or second-guess. A test-only dependency is a very different risk \
than one shipped to production; weigh scope accordingly from the start.

From there, work through the rest of the investigation like a real analyst would:
1. Check whether the vulnerable package is actually referenced in this \
   project's own source (reachability) — search for the artifact id and, if \
   the advisory names a specific vulnerable class/method, search for that too.
2. Check KEV status and EPSS score to gauge real-world exploitation risk, \
   not just theoretical severity.
3. Check whether a fixed version is available.

Use the tools to gather this evidence before concluding. Don't guess at \
information a tool can give you. When you've gathered enough evidence, \
produce your final verdict."""


class TriageVerdict(BaseModel):
    severity: str = Field(description="e.g. Critical / High / Medium / Low")
    reachable: str = Field(description="Yes / No / Unclear, with one-line justification")
    actively_exploited: bool = Field(description="True if in KEV or credible evidence of real-world exploitation")
    epss_score: str | None = Field(default=None, description="EPSS score if it was looked up")
    recommended_action: str = Field(description="e.g. Upgrade immediately / Upgrade in next cycle / Mitigate / Accept risk / Needs human review")
    fixed_version: str | None = Field(default=None)
    rationale: str = Field(description="2-4 sentences citing the specific evidence gathered")


def build_agent():
    api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Set GOOGLE_API_KEY (or GEMINI_API_KEY) in your environment — "
            "get a free key from Google AI Studio."
        )
    # Explicit timeout + low max_retries so a bad model/network fails fast
    # and visibly, instead of retrying silently for minutes (default
    # max_retries is 6, which is what made the hang look like a freeze).
    llm = ChatGoogleGenerativeAI(
        model=GEMINI_MODEL,
        google_api_key=api_key,
        timeout=60,
        max_retries=2,
    )
    return create_agent(
        model=llm,
        tools=ALL_TOOLS,
        system_prompt=SYSTEM_PROMPT,
        response_format=TriageVerdict,
    )


def _build_seed_message(alert: dict, coord: str) -> str:
    """Embeds dependency context + trimmed advisory detail directly, instead
    of making the agent spend its first two tool calls fetching data that's
    already fully known and deterministic right after scanning. Same fields
    the old get_dependency_context/get_advisory_detail tools used to return."""
    dep = alert["dependency"]
    advisories = [
        {
            "id": v["id"],
            "aliases": v["aliases"],
            "summary": v["summary"],
            "details": (v["details"] or "")[:800],
            "cwe_ids": v["cwe_ids"],
            "severity": v["severity"],
            "references": v["references"][:5],
        }
        for v in alert["vulnerabilities"]
    ]
    return (
        f"Investigate this alert: {coord}.\n\n"
        f"Dependency context (already known, do not look this up):\n"
        f"{json.dumps(dep, indent=2)}\n\n"
        f"Advisory detail (already known, do not look this up):\n"
        f"{json.dumps(advisories, indent=2)}\n\n"
        f"Continue the investigation from here using the available tools."
    )


def triage_one(agent, alert: dict) -> dict:
    """alert: one entry from results/alerts.json (dependency + vulnerabilities)
    — runs the full investigation and returns
    {'verdict': TriageVerdict, 'trace': [messages]}.
    Prints step-by-step progress and writes every LLM/tool call to
    results/llm/<dependency>/ so a slow or stuck run is visible, not silent."""
    dep = alert["dependency"]
    coord = f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}"
    label = coord.replace(":", "_")
    callback = TriageLoggingCallback(label=coord, log_dir=LLM_LOG_DIR / label)

    user_msg = _build_seed_message(alert, coord)
    result = agent.invoke(
        {"messages": [{"role": "user", "content": user_msg}]},
        config={"callbacks": [callback], "recursion_limit": 15},
    )
    return {
        "dependency": coord,
        "verdict": result["structured_response"].model_dump(),
        "trace": [
            {"type": m.type, "content": getattr(m, "content", "")}
            for m in result["messages"]
        ],
    }
