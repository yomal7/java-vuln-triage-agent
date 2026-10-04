"""Dependency-level aggregation.

The agent triages one *dependency* per run, but a dependency carries many
vulnerabilities (log4j-core 8, jackson-databind 55). The slot rules need one
answer per dependency, so these helpers collapse per-vulnerability data.
Every function also returns coverage counts so the thesis can state exactly
how much evidence stood behind each "resolved".

Rules (documented design choices):
  exploitation  resolved if ANY vulnerability is in KEV or ANY has an EPSS score
  fix           resolved if ANY vulnerability has a concrete fixed version
  reachability  confirmed  if ANY vulnerability is confirmed reachable
                ambiguous  if none confirmed but ANY ambiguous
                error      if none of the above but ANY error / no result
                absent     only if EVERY vulnerability is absent
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

WILDCARD = "*"


def _blank(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.strip() == "")


def aggregate_exploitation(vulns: List[Mapping[str, Any]]) -> Dict[str, Any]:
    scored = [v["epss_score"] for v in vulns if v.get("epss_score") is not None]
    kev = sum(1 for v in vulns if v.get("in_kev") is True)
    return {
        "in_kev": kev > 0,
        "epss_score": max(scored) if scored else None,
        "coverage": {"vulnerabilities": len(vulns), "in_kev": kev, "with_epss": len(scored)},
    }


def aggregate_fix(vulns: List[Mapping[str, Any]]) -> Dict[str, Any]:
    hints = [v.get("fixed_version_hint") for v in vulns if not _blank(v.get("fixed_version_hint"))]
    return {
        "fixed_version_hint": hints[0] if hints else None,
        "coverage": {"vulnerabilities": len(vulns), "with_fix": len(hints)},
    }


def load_reachability(path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Return the `results` list from a reachability.json file ([] if absent)."""
    p = Path(path)
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8")).get("results", [])


def _same_dependency(entry: Mapping[str, Any], dep: Mapping[str, Any]) -> bool:
    d = entry.get("dependency", {})
    return all(d.get(k) == dep.get(k) for k in ("group_id", "artifact_id", "version"))


def aggregate_reachability(
    results: Iterable[Mapping[str, Any]],
    dependency: Mapping[str, Any],
    vuln_ids: List[str],
) -> Dict[str, Any]:
    """Collapse per-vulnerability reachability entries for one dependency.

    An entry with vulnerability_id "*" applies to every vulnerability of the
    dependency unless a more specific entry exists for that vulnerability.
    """
    mine = [r for r in results if _same_dependency(r, dependency)]
    wildcard = next((r for r in mine if r.get("vulnerability_id") == WILDCARD), None)
    specific = {r["vulnerability_id"]: r for r in mine if r.get("vulnerability_id") != WILDCARD}

    counts = {"confirmed": 0, "absent": 0, "ambiguous": 0, "error": 0, "missing": 0}
    for vid in vuln_ids:
        entry = specific.get(vid) or wildcard
        if entry is None:
            counts["missing"] += 1
            continue
        status = entry.get("status")
        counts[status if status in counts else "error"] += 1

    if counts["confirmed"]:
        status = "confirmed"
    elif counts["ambiguous"]:
        status = "ambiguous"
    elif counts["error"] or counts["missing"]:
        status = "error"
    else:
        status = "absent"
    return {"status": status, "counts": counts}
