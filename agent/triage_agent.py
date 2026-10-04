"""
triage_agent.py — the ReAct triage loop.

Deliberately has NO escalation/interrupt logic — this spike is just about
learning what an automated investigation looks like. Uses the current
(2026) langchain API: `langchain.agents.create_agent`, NOT the deprecated
`langgraph.prebuilt.create_react_agent` (that path is removed in LangGraph
V2.0; verified against the actually-installed package version, not memory).
"""
import json
import sys
import time
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from llm import build_llm_stack  # noqa: E402
from logging_callback import TriageLoggingCallback  # noqa: E402
from protocol.session import Investigation  # noqa: E402
from protocol.verdict import TriageVerdict  # noqa: E402
from tools import ALL_TOOLS  # noqa: E402

# Model, provider, retries, rate cap and fallback chain are all configured in
# .env — see the docstring at the top of llm.py. If a model 404s, run
# `python agent/list_models.py` to see what your key can actually use.

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
information a tool can give you.

If the first message lists environment facts about the affected asset, treat \
them as verified and let them shape severity and urgency. Anything about the \
asset that is NOT listed is unknown to you: do not assume it, and say in your \
rationale which facts were unknown. If an analyst later answers questions, \
treat those answers as verified facts too.

When you've gathered enough evidence, produce your final verdict, choosing \
only from the allowed options for severity, reachable and recommended_action."""


def build_agent():
    """Returns (agent, llm_stack). The stack carries the retry/fallback/rate-limit
    middleware and the settings that get recorded in every run file."""
    stack = build_llm_stack()
    agent = create_agent(
        model=stack.model,
        tools=ALL_TOOLS,
        system_prompt=SYSTEM_PROMPT,
        response_format=TriageVerdict,
        middleware=stack.middleware,
    )
    return agent, stack


def _build_seed_message(alert: dict, coord: str, environment: dict | None = None) -> str:
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
    env_block = ""
    if environment is not None:
        env_block = (
            "Environment facts about the affected asset (verified; anything not "
            "listed here is UNKNOWN to you):\n"
            f"{json.dumps(environment, indent=2)}\n\n"
        )
    return (
        f"Investigate this alert: {coord}.\n\n"
        f"Dependency context (already known, do not look this up):\n"
        f"{json.dumps(dep, indent=2)}\n\n"
        f"{env_block}"
        f"Advisory detail (already known, do not look this up):\n"
        f"{json.dumps(advisories, indent=2)}\n\n"
        f"Continue the investigation from here using the available tools."
    )


def _models_used(messages) -> list:
    return sorted({
        (m.response_metadata or {}).get("model_name")
        for m in messages
        if m.type == "ai" and (m.response_metadata or {}).get("model_name")
    })


def _coord(alert: dict) -> str:
    dep = alert["dependency"]
    return f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}"


def investigate(agent, alert: dict, environment: dict | None = None, callback=None) -> dict:
    """First pass: run the full ReAct investigation. Returns the raw result."""
    coord = _coord(alert)
    result = agent.invoke(
        {"messages": [{"role": "user", "content": _build_seed_message(alert, coord, environment)}]},
        config={"callbacks": [callback] if callback else [], "recursion_limit": 15},
    )
    return result


def resume_investigation(agent, messages, human_text: str, callback=None) -> dict:
    """Continue the SAME investigation: the full earlier message history (tool calls
    and results included) plus the analyst's answers. Nothing is reconstructed."""
    result = agent.invoke(
        {"messages": list(messages) + [HumanMessage(content=human_text)]},
        config={"callbacks": [callback] if callback else [], "recursion_limit": 15},
    )
    return result


def triage_one(agent, alert: dict, llm_info: dict | None = None) -> dict:
    """alert: one entry from results/alerts.json (dependency + vulnerabilities)
    — runs the full investigation and returns
    {'verdict': TriageVerdict, 'trace': [messages]}.
    Prints step-by-step progress and writes every LLM/tool call to
    results/llm/<dependency>/ so a slow or stuck run is visible, not silent."""
    coord = _coord(alert)
    label = coord.replace(":", "_")
    callback = TriageLoggingCallback(label=coord, log_dir=LLM_LOG_DIR / label)
    result = investigate(agent, alert, None, callback)
    return {
        "dependency": coord,
        "llm": {**(llm_info or {}), "models_used": _models_used(result["messages"])},
        "verdict": result["structured_response"].model_dump(),
        "trace": [
            {"type": m.type, "content": getattr(m, "content", "")}
            for m in result["messages"]
        ],
    }


class LangChainEngine:
    """Adapter that lets protocol.session drive the real agent.

    One instance per study case: it owns one logging callback, so the step
    numbering in the log folder continues across the first pass and the resume.
    """

    def __init__(self, agent, stack, label: str, log_dir: Path):
        self.agent = agent
        self.stack = stack
        self.callback = TriageLoggingCallback(label=label, log_dir=log_dir)

    def _package(self, result, t0: float, wait0: float) -> Investigation:
        return Investigation(
            verdict=result["structured_response"].model_dump(),
            messages=list(result["messages"]),
            duration_s=time.monotonic() - t0,
            rate_limit_wait_s=self.stack.rate_limit.total_wait_seconds - wait0,
            models_used=_models_used(result["messages"]),
        )

    def investigate(self, alert, environment) -> Investigation:
        t0, w0 = time.monotonic(), self.stack.rate_limit.total_wait_seconds
        return self._package(investigate(self.agent, alert, environment, self.callback), t0, w0)

    def resume(self, messages, human_text) -> Investigation:
        t0, w0 = time.monotonic(), self.stack.rate_limit.total_wait_seconds
        return self._package(resume_investigation(self.agent, messages, human_text, self.callback), t0, w0)
