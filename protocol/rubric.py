"""Triage rubric: the ground truth for accuracy, as code.

Adapted from the SSVC deployer decision points (Spring et al., 2021). The SAME
text is given to the agent (POLICY_TEXT), so the agent and the ground truth share
one source, as a SOC playbook would. First matching rule wins.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

EPSS_HIGH = 0.1  # draft threshold, to be confirmed
NOT_SHIPPED = {"test", "provided"}

POLICY_TEXT = """Triage policy (apply the first rule that matches):
1. Dependency not shipped (scope test or provided): Accept risk.
2. Vulnerable code not reachable: Upgrade in next cycle (Accept risk if no fixed version).
3. Reachable, listed in KEV, and the asset is internet-facing: Upgrade immediately (Mitigate if no fixed version).
4. Reachable, in KEV or any EPSS score >= 0.1, and asset criticality high or critical: Upgrade immediately (Mitigate if no fixed version).
5. Reachable, any other case: Upgrade in next cycle (Mitigate if no fixed version).
6. Reachability still unclear after all evidence and analyst answers: Needs human review."""


def expected_verdict(
    *,
    scope: str,
    reachable: str,                 # "yes" | "no" | anything else = unclear
    in_kev: bool,
    max_epss: Optional[float],
    exposure: Optional[str],
    criticality: Optional[str],
    fix_available: bool,
    epss_high: float = EPSS_HIGH,
) -> Dict[str, Any]:
    reach_label = {"yes": "Yes", "no": "No"}.get(reachable, "Unclear")

    def out(action: str, rule: int) -> Dict[str, Any]:
        return {"reachable": reach_label, "recommended_action": action, "rule": rule}

    def act(with_fix: str, without_fix: str) -> str:
        return with_fix if fix_available else without_fix

    if scope in NOT_SHIPPED:
        return out("Accept risk", 1)
    if reachable == "no":
        return out(act("Upgrade in next cycle", "Accept risk"), 2)
    if reachable == "yes":
        if in_kev and exposure == "internet_facing":
            return out(act("Upgrade immediately", "Mitigate"), 3)
        if (in_kev or (max_epss or 0.0) >= epss_high) and criticality in ("high", "critical"):
            return out(act("Upgrade immediately", "Mitigate"), 4)
        return out(act("Upgrade in next cycle", "Mitigate"), 5)
    return out("Needs human review", 6)