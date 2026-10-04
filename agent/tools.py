"""
tools.py — the four tools the triage agent can call.

Dependency context and advisory detail used to be tools here too
(get_dependency_context, get_advisory_detail) — both were pure lookups
into alerts.json with no judgment involved, so they're now embedded
directly in the seed message the agent starts with (see
triage_agent.py:_build_seed_message) instead of costing a tool-call
round-trip each. Same for EPSS: it used to be a live per-CVE HTTP call
during the loop; scanner/scan.py now prefetches it alongside KEV, so
check_exploit_maturity below is just a local lookup like check_kev_status.

Only search_code_usage still does a live, non-prefetched action, because
it depends on the codebase, not the advisory data.
"""
import json
import os
import sys
from pathlib import Path

from langchain_core.tools import tool

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol.aggregate import (  # noqa: E402
    aggregate_reachability,
    entries_for_dependency,
    load_reachability,
)

RESULTS_DIR = ROOT / "results"
REACHABILITY_PATH = Path(os.environ.get("REACHABILITY_FILE", RESULTS_DIR / "reachability.json"))
TARGET_PROJECT_SRC = ROOT / "target-project" / "src"

try:
    _ALERTS = json.loads((RESULTS_DIR / "alerts.json").read_text())
    _DEP_TREE = json.loads((RESULTS_DIR / "dependency_tree.json").read_text())
except FileNotFoundError as e:
    raise RuntimeError(
        "results/alerts.json (or dependency_tree.json) not found — "
        "run `python scanner/scan.py` first."
    ) from e


def _find_alert(group_id: str, artifact_id: str, version: str) -> dict | None:
    for a in _ALERTS:
        d = a["dependency"]
        if d["group_id"] == group_id and d["artifact_id"] == artifact_id and d["version"] == version:
            return a
    # Small models occasionally garble one coordinate when retyping it (seen live:
    # group_id came back as "org.springframework:`,version:"). A UNIQUE artifact+version
    # match is safe to accept; anything ambiguous is still refused.
    candidates = [
        a for a in _ALERTS
        if a["dependency"]["artifact_id"] == artifact_id and a["dependency"]["version"] == version
    ]
    return candidates[0] if len(candidates) == 1 else None


def _unknown(group_id: str, artifact_id: str, version: str) -> str:
    known = ", ".join(
        f"{a['dependency']['group_id']}:{a['dependency']['artifact_id']}:{a['dependency']['version']}"
        for a in _ALERTS
    )
    return (
        f"unknown — no advisory data for {group_id}:{artifact_id}:{version}. "
        f"Check the coordinates; known dependencies: {known}"
    )


@tool
def check_kev_status(group_id: str, artifact_id: str, version: str) -> str:
    """Check whether any CVE affecting this dependency+version is in CISA's
    Known Exploited Vulnerabilities (KEV) catalog — i.e. confirmed active
    exploitation in the wild, not just theoretical risk."""
    alert = _find_alert(group_id, artifact_id, version)
    if not alert:
        return _unknown(group_id, artifact_id, version)
    flags = {v["id"]: v["in_kev"] for v in alert["vulnerabilities"]}
    return json.dumps(flags, indent=2)


@tool
def check_fix_version(group_id: str, artifact_id: str, version: str) -> str:
    """Look up the nearest patched version that resolves the known
    vulnerabilities for this dependency, if OSV's advisory data specifies
    one. May return null if the advisory doesn't record a fixed version."""
    alert = _find_alert(group_id, artifact_id, version)
    if not alert:
        return _unknown(group_id, artifact_id, version)
    hints = {v["id"]: v.get("fixed_version_hint") for v in alert["vulnerabilities"]}
    return json.dumps(hints, indent=2)


@tool
def check_exploit_maturity(group_id: str, artifact_id: str, version: str) -> str:
    """Look up the EPSS score for every CVE affecting this dependency+version
    — the modeled probability (0-1) that it will be exploited in the wild in
    the next 30 days. Prefetched by the scanner alongside KEV, so this is an
    instant lookup, not a live API call. Null means FIRST.org had no score
    for that CVE (e.g. too new, or GHSA-only with no CVE alias)."""
    alert = _find_alert(group_id, artifact_id, version)
    if not alert:
        return _unknown(group_id, artifact_id, version)
    scores = {v["id"]: v.get("epss_score") for v in alert["vulnerabilities"]}
    return json.dumps(scores, indent=2)


@tool
def check_reachability(group_id: str, artifact_id: str, version: str) -> str:
    """Check whether the vulnerable functionality of this dependency is
    reachable from the target project's own code, using a PRECOMPUTED static
    analysis (instant lookup). status is one of:
      confirmed - a path to vulnerable code exists
      absent    - no path was found (static analysis; not an absolute proof)
      ambiguous - the analysis could not decide; do NOT assume either way
      error     - no usable result
    Also returns a reason and any evidence per vulnerability."""
    alert = _find_alert(group_id, artifact_id, version)
    if not alert:
        return _unknown(group_id, artifact_id, version)
    dep = alert["dependency"]
    results = load_reachability(REACHABILITY_PATH)
    agg = aggregate_reachability(results, dep, [v["id"] for v in alert["vulnerabilities"]])
    details = [
        {
            "vulnerability_id": r.get("vulnerability_id"),
            "status": r.get("status"),
            "reason": r.get("reason"),
            "ambiguity_cause": r.get("ambiguity_cause"),
            "evidence": r.get("evidence", []),
        }
        for r in entries_for_dependency(results, dep)
    ]
    return json.dumps(
        {"dependency": f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}", "status": agg["status"],
         "counts": agg["counts"], "details": details},
        indent=2,
    )


@tool
def search_code_usage(artifact_id: str, symbol_hint: str = "") -> str:
    """Grep the target project's own source tree for imports/usages that
    reference this dependency. A crude but real reachability signal: if
    nothing in our own code imports it, the vulnerable code path likely
    isn't exercised even though the dependency is on the classpath.
    symbol_hint: an optional specific class/package name to search for
    (e.g. a class named in the advisory)."""
    if not TARGET_PROJECT_SRC.exists():
        return "target project source tree not found"
    pattern = symbol_hint if symbol_hint else artifact_id
    matches = []
    for path in TARGET_PROJECT_SRC.rglob("*.java"):
        text = path.read_text(errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.lower() in line.lower():
                matches.append(f"{path.relative_to(TARGET_PROJECT_SRC)}:{lineno}: {line.strip()}")
    if not matches:
        return f"No references to '{pattern}' found anywhere in source"
    return "\n".join(matches[:30])


def reachability_source() -> str:
    """'stored' (default): the agent reads the precomputed reachability.json, the same
    evidence the slot check uses. 'grep': the original v1 text-search tool, kept as the
    baseline for the v1-vs-engine comparison."""
    src = os.environ.get("REACHABILITY_SOURCE", "stored").strip().lower()
    if src not in ("stored", "grep"):
        raise ValueError(f"REACHABILITY_SOURCE must be 'stored' or 'grep', got {src!r}")
    return src


def get_tools() -> list:
    reach = search_code_usage if reachability_source() == "grep" else check_reachability
    return [check_kev_status, check_fix_version, check_exploit_maturity, reach]


ALL_TOOLS = get_tools()