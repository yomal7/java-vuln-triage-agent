"""One slot report per dependency (JSON-serialisable).

Used in shadow mode: the report is recorded next to the agent's verdict but does
not change the agent's behaviour. Later the escalation layer reads the same report.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Optional

from .aggregate import aggregate_exploitation, aggregate_fix, aggregate_reachability
from .slots import evaluate_slots


def dependency_slot_report(
    alert: Mapping[str, Any],
    reachability_results: Iterable[Mapping[str, Any]],
    environment: Optional[Mapping[str, Any]],
    gate_environment_on_absent: bool = False,
) -> Dict[str, Any]:
    dep = alert["dependency"]
    vulns = alert["vulnerabilities"]
    expl = aggregate_exploitation(vulns)
    fix = aggregate_fix(vulns)
    reach = aggregate_reachability(reachability_results, dep, [v["id"] for v in vulns])

    report = evaluate_slots(
        in_kev=expl["in_kev"],
        epss_score=expl["epss_score"],
        fixed_version_hint=fix["fixed_version_hint"],
        reachability={"status": reach["status"]},
        environment=environment,
        gate_environment_on_absent=gate_environment_on_absent,
    )
    return {
        "dependency": f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}",
        "needs_escalation": report.needs_escalation,
        "unresolved": [s.value for s in report.unresolved],
        "slots": {r.slot.value: {"state": r.state.value, "reason": r.reason} for r in report.results},
        "coverage": {
            "exploitation": expl["coverage"],
            "fix": fix["coverage"],
            "reachability": reach["counts"],
        },
    }
