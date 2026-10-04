"""Required-slot checker for the micro-escalation protocol.

Pure functions: no I/O and no LLM calls. Given the evidence gathered so far,
every slot is RESOLVED, UNRESOLVED or NOT_REQUIRED. A required slot that is
UNRESOLVED is an escalation trigger.

Slots (derived from the RQ1 conditions):
  tool slots         reachability, exploitation_status, fix_availability
  environment slots  network_exposure, asset_criticality, patch_window

Reachability contract (engine-independent): a mapping with a "status" key whose
value is one of "confirmed", "absent", "ambiguous", "error". Whatever produces
reachability today (search_code_usage) or later (a call-graph engine reading
reachability.json) must return this shape.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Tuple


class Slot(str, Enum):
    REACHABILITY = "reachability"
    EXPLOITATION = "exploitation_status"
    FIX_AVAILABILITY = "fix_availability"
    NETWORK_EXPOSURE = "network_exposure"
    ASSET_CRITICALITY = "asset_criticality"
    PATCH_WINDOW = "patch_window"


class State(str, Enum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    NOT_REQUIRED = "not_required"


TOOL_SLOTS = (Slot.REACHABILITY, Slot.EXPLOITATION, Slot.FIX_AVAILABILITY)
ENVIRONMENT_SLOTS = (Slot.NETWORK_EXPOSURE, Slot.ASSET_CRITICALITY, Slot.PATCH_WINDOW)

# Environment slot -> field name in the asset record.
ENV_FIELD = {
    Slot.NETWORK_EXPOSURE: "network_exposure",
    Slot.ASSET_CRITICALITY: "asset_criticality",
    Slot.PATCH_WINDOW: "patch_window",
}

# Controlled vocabularies (None = free text). A value outside the vocabulary is
# treated as unresolved so typos in scenario data cannot silently pass.
_ALLOWED = {
    Slot.NETWORK_EXPOSURE: {"internet_facing", "internal", "isolated"},
    Slot.ASSET_CRITICALITY: {"low", "medium", "high", "critical"},
    Slot.PATCH_WINDOW: None,
}

REACHABILITY_RESOLVED = {"confirmed", "absent"}
REACHABILITY_STATUSES = REACHABILITY_RESOLVED | {"ambiguous", "error"}


@dataclass(frozen=True)
class SlotResult:
    slot: Slot
    state: State
    reason: str
    value: Any = None


@dataclass(frozen=True)
class SlotReport:
    results: Tuple[SlotResult, ...]

    def get(self, slot: Slot) -> SlotResult:
        for r in self.results:
            if r.slot == slot:
                return r
        raise KeyError(slot)

    @property
    def unresolved(self) -> Tuple[Slot, ...]:
        """Unresolved slots in priority order (tool slots first)."""
        return tuple(r.slot for r in self.results if r.state == State.UNRESOLVED)

    @property
    def needs_escalation(self) -> bool:
        return bool(self.unresolved)


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and value.strip() == "")


def check_reachability(reach: Optional[Mapping[str, Any]]) -> SlotResult:
    if not reach:
        return SlotResult(Slot.REACHABILITY, State.UNRESOLVED, "no reachability result available")
    status = reach.get("status")
    if status in REACHABILITY_RESOLVED:
        return SlotResult(Slot.REACHABILITY, State.RESOLVED, f"reachability status is {status}", status)
    if status in REACHABILITY_STATUSES:
        return SlotResult(Slot.REACHABILITY, State.UNRESOLVED, f"reachability status is {status}", status)
    return SlotResult(Slot.REACHABILITY, State.UNRESOLVED, f"unrecognised reachability status: {status!r}")


def check_exploitation(in_kev: Optional[bool], epss_score: Optional[float]) -> SlotResult:
    value = {"in_kev": in_kev, "epss_score": epss_score}
    if in_kev is True:
        return SlotResult(Slot.EXPLOITATION, State.RESOLVED, "listed in CISA KEV", value)
    if epss_score is not None:
        return SlotResult(Slot.EXPLOITATION, State.RESOLVED, "EPSS score present", value)
    return SlotResult(Slot.EXPLOITATION, State.UNRESOLVED, "not in KEV and no EPSS score", value)


def check_fix(fixed_version_hint: Optional[str]) -> SlotResult:
    if _blank(fixed_version_hint):
        return SlotResult(Slot.FIX_AVAILABILITY, State.UNRESOLVED, "no fixed version identified")
    return SlotResult(Slot.FIX_AVAILABILITY, State.RESOLVED, "fixed version identified", fixed_version_hint)


def check_environment(slot: Slot, environment: Optional[Mapping[str, Any]]) -> SlotResult:
    field = ENV_FIELD[slot]
    if environment is None:
        return SlotResult(slot, State.UNRESOLVED, "no environment record available")
    value = environment.get(field)
    if _blank(value):
        return SlotResult(slot, State.UNRESOLVED, f"{field} is missing")
    allowed = _ALLOWED[slot]
    if allowed is not None and value not in allowed:
        return SlotResult(slot, State.UNRESOLVED, f"unrecognised value for {field}: {value!r}")
    return SlotResult(slot, State.RESOLVED, f"{field} is present", value)


def evaluate_slots(
    *,
    in_kev: Optional[bool],
    epss_score: Optional[float],
    fixed_version_hint: Optional[str],
    reachability: Optional[Mapping[str, Any]],
    environment: Optional[Mapping[str, Any]],
    gate_environment_on_absent: bool = False,
) -> SlotReport:
    """Evaluate all six slots.

    gate_environment_on_absent: when True and reachability is confirmed absent,
    the environment slots are NOT_REQUIRED (no questions asked). Off by default;
    it is a design choice to be decided, because a wrong "absent" would suppress
    questions that matter.
    """
    reach_result = check_reachability(reachability)
    results = [
        reach_result,
        check_exploitation(in_kev, epss_score),
        check_fix(fixed_version_hint),
    ]
    gated = (
        gate_environment_on_absent
        and reach_result.state == State.RESOLVED
        and reach_result.value == "absent"
    )
    for slot in ENVIRONMENT_SLOTS:
        if gated:
            results.append(
                SlotResult(slot, State.NOT_REQUIRED, "gated off: reachability confirmed absent")
            )
        else:
            results.append(check_environment(slot, environment))
    return SlotReport(tuple(results))
