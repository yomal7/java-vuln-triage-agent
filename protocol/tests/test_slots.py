from pathlib import Path

import pytest

from protocol.environment import KNOWN_FIELDS, agent_view, fact_sheet, load_assets
from protocol.slots import (
    ENV_FIELD,
    Slot,
    State,
    check_environment,
    check_exploitation,
    check_fix,
    check_reachability,
    evaluate_slots,
)

DATA = Path(__file__).resolve().parent.parent / "data" / "environment.example.json"
FULL_ENV = {
    "network_exposure": "internet_facing",
    "asset_criticality": "high",
    "patch_window": "monthly",
}


# ---- reachability -------------------------------------------------------

@pytest.mark.parametrize("status", ["confirmed", "absent"])
def test_reachability_resolved(status):
    assert check_reachability({"status": status}).state == State.RESOLVED


@pytest.mark.parametrize("status", ["ambiguous", "error"])
def test_reachability_unresolved(status):
    assert check_reachability({"status": status}).state == State.UNRESOLVED


@pytest.mark.parametrize("bad", [None, {}, {"status": "maybe"}])
def test_reachability_missing_or_unknown_is_unresolved(bad):
    assert check_reachability(bad).state == State.UNRESOLVED


# ---- exploitation -------------------------------------------------------

def test_exploitation_kev_true_without_epss_is_resolved():
    # The gap in the original table: KEV true + EPSS null must count as resolved.
    assert check_exploitation(True, None).state == State.RESOLVED


def test_exploitation_epss_present_is_resolved():
    assert check_exploitation(False, 0.01268).state == State.RESOLVED


def test_exploitation_zero_epss_is_still_a_score():
    assert check_exploitation(False, 0.0).state == State.RESOLVED


def test_exploitation_no_evidence_is_unresolved():
    assert check_exploitation(False, None).state == State.UNRESOLVED


# ---- fix availability ---------------------------------------------------

def test_fix_resolved():
    assert check_fix("5.2.19.RELEASE").state == State.RESOLVED


@pytest.mark.parametrize("hint", [None, "", "   "])
def test_fix_unresolved(hint):
    assert check_fix(hint).state == State.UNRESOLVED


# ---- environment slots --------------------------------------------------

def test_environment_resolved_when_present():
    assert check_environment(Slot.NETWORK_EXPOSURE, FULL_ENV).state == State.RESOLVED


def test_environment_unresolved_when_field_missing():
    env = dict(FULL_ENV)
    del env["asset_criticality"]
    assert check_environment(Slot.ASSET_CRITICALITY, env).state == State.UNRESOLVED


def test_environment_unresolved_when_no_record():
    assert check_environment(Slot.PATCH_WINDOW, None).state == State.UNRESOLVED


def test_environment_unrecognised_value_is_unresolved():
    env = dict(FULL_ENV, network_exposure="dmz-ish")
    assert check_environment(Slot.NETWORK_EXPOSURE, env).state == State.UNRESOLVED


# ---- whole report -------------------------------------------------------

def _eval(**overrides):
    args = dict(
        in_kev=False,
        epss_score=0.01,
        fixed_version_hint="1.2.3",
        reachability={"status": "confirmed"},
        environment=FULL_ENV,
    )
    args.update(overrides)
    return evaluate_slots(**args)


def test_all_resolved_means_no_escalation():
    report = _eval()
    assert report.unresolved == ()
    assert not report.needs_escalation


def test_unresolved_slots_keep_priority_order():
    report = _eval(
        reachability={"status": "ambiguous"},
        fixed_version_hint=None,
        environment={"patch_window": "monthly"},
    )
    assert report.unresolved == (
        Slot.REACHABILITY,
        Slot.FIX_AVAILABILITY,
        Slot.NETWORK_EXPOSURE,
        Slot.ASSET_CRITICALITY,
    )
    assert report.needs_escalation


def test_gate_is_off_by_default():
    report = _eval(reachability={"status": "absent"}, environment={})
    assert Slot.NETWORK_EXPOSURE in report.unresolved


def test_gate_on_skips_environment_slots_when_absent():
    report = _eval(
        reachability={"status": "absent"}, environment={}, gate_environment_on_absent=True
    )
    assert report.unresolved == ()
    assert report.get(Slot.NETWORK_EXPOSURE).state == State.NOT_REQUIRED


def test_gate_on_does_not_skip_when_ambiguous():
    report = _eval(
        reachability={"status": "ambiguous"}, environment={}, gate_environment_on_absent=True
    )
    assert Slot.NETWORK_EXPOSURE in report.unresolved


# ---- mock environment masking ------------------------------------------

def test_agent_view_removes_withheld_fields():
    facts = load_assets(DATA)["mock-app-01"]
    view = agent_view(facts, ["network_exposure"])
    assert "network_exposure" not in view
    assert fact_sheet(facts)["network_exposure"] == "internet_facing"


def test_withheld_field_triggers_the_matching_slot():
    facts = load_assets(DATA)["mock-app-01"]
    report = _eval(environment=agent_view(facts, ["asset_criticality"]))
    assert report.unresolved == (Slot.ASSET_CRITICALITY,)


def test_agent_view_rejects_unknown_field():
    with pytest.raises(ValueError):
        agent_view(FULL_ENV, ["nework_exposure"])


def test_slot_and_environment_field_names_agree():
    assert set(KNOWN_FIELDS) == set(ENV_FIELD.values())
    for asset in load_assets(DATA).values():
        for field in KNOWN_FIELDS:
            assert field in asset