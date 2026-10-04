"""Fixed-option verdict schema and scoring.

Free-text verdict fields cannot be scored against ground truth, so the three
fields RQ3 accuracy depends on are closed vocabularies.
"""
from __future__ import annotations

from typing import Any, Dict, Literal, Mapping, Optional

from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low"]
Reachable = Literal["Yes", "No", "Unclear"]
Action = Literal[
    "Upgrade immediately",
    "Upgrade in next cycle",
    "Mitigate",
    "Accept risk",
    "Needs human review",
]

SEVERITIES = ("Critical", "High", "Medium", "Low")
REACHABLE_OPTIONS = ("Yes", "No", "Unclear")
ACTIONS = (
    "Upgrade immediately",
    "Upgrade in next cycle",
    "Mitigate",
    "Accept risk",
    "Needs human review",
)
SCORED_FIELDS = ("reachable", "recommended_action", "severity")
VOCABULARY = {
    "severity": SEVERITIES,
    "reachable": REACHABLE_OPTIONS,
    "recommended_action": ACTIONS,
}


class TriageVerdict(BaseModel):
    severity: Severity = Field(description="Critical, High, Medium or Low, weighing the environment facts you were given")
    reachable: Reachable = Field(description="Yes, No or Unclear: is the vulnerable functionality actually used?")
    reachable_justification: str = Field(description="One line explaining the reachability answer")
    actively_exploited: bool = Field(description="True if in KEV or credible evidence of real-world exploitation")
    epss_score: Optional[str] = Field(default=None, description="EPSS score if it was looked up")
    recommended_action: Action = Field(description="Exactly one of the allowed actions")
    fixed_version: Optional[str] = Field(default=None)
    rationale: str = Field(description="2-4 sentences citing the specific evidence gathered and any facts that were unknown")


def score_verdict(verdict: Mapping[str, Any], expected: Mapping[str, str]) -> Dict[str, Any]:
    """Field-wise correctness against the scenario's expected values.

    Only fields present in `expected` are scored. `exact` is True when every
    scored field is correct (None if nothing was scored).
    """
    checks = {f: verdict.get(f) == expected[f] for f in SCORED_FIELDS if f in expected}
    out: Dict[str, Any] = {f"{f}_correct": ok for f, ok in checks.items()}
    out["exact"] = all(checks.values()) if checks else None
    return out
