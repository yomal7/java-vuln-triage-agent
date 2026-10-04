import json
from pathlib import Path

import pytest

from protocol.aggregate import (
    aggregate_exploitation,
    aggregate_fix,
    aggregate_reachability,
    load_reachability,
)
from protocol.report import dependency_slot_report

ROOT = Path(__file__).resolve().parent.parent.parent
DEP = {"group_id": "g", "artifact_id": "a", "version": "1"}
ENV = {"network_exposure": "internal", "asset_criticality": "low", "patch_window": "monthly"}


def entry(status, vid="*", dep=DEP):
    return {"dependency": dep, "vulnerability_id": vid, "status": status}


# ---- exploitation / fix -------------------------------------------------

def test_exploitation_any_kev_or_any_epss_resolves():
    vulns = [{"in_kev": False, "epss_score": None}, {"in_kev": False, "epss_score": 0.2}]
    out = aggregate_exploitation(vulns)
    assert out["epss_score"] == 0.2
    assert out["coverage"] == {"vulnerabilities": 2, "in_kev": 0, "with_epss": 1}


def test_exploitation_no_signal_at_all():
    out = aggregate_exploitation([{"in_kev": False, "epss_score": None}])
    assert out["in_kev"] is False and out["epss_score"] is None


def test_fix_takes_any_concrete_hint():
    out = aggregate_fix([{"fixed_version_hint": None}, {"fixed_version_hint": "2.0"}, {"fixed_version_hint": ""}])
    assert out["fixed_version_hint"] == "2.0"
    assert out["coverage"] == {"vulnerabilities": 3, "with_fix": 1}


# ---- reachability aggregation ------------------------------------------

def test_wildcard_entry_covers_every_vulnerability():
    out = aggregate_reachability([entry("absent")], DEP, ["v1", "v2", "v3"])
    assert out["status"] == "absent"
    assert out["counts"]["absent"] == 3


def test_specific_entry_overrides_wildcard():
    results = [entry("absent"), entry("confirmed", vid="v2")]
    out = aggregate_reachability(results, DEP, ["v1", "v2"])
    assert out["status"] == "confirmed"


def test_confirmed_beats_ambiguous_beats_error_beats_absent():
    ids = ["v1", "v2", "v3", "v4"]
    base = [entry("absent", "v1"), entry("error", "v2"), entry("ambiguous", "v3")]
    assert aggregate_reachability(base, DEP, ids[:3])["status"] == "ambiguous"
    assert aggregate_reachability(base[:2], DEP, ids[:2])["status"] == "error"
    assert aggregate_reachability(base + [entry("confirmed", "v4")], DEP, ids)["status"] == "confirmed"


def test_missing_result_is_an_error_not_absent():
    out = aggregate_reachability([], DEP, ["v1"])
    assert out["status"] == "error"
    assert out["counts"]["missing"] == 1


def test_other_dependencies_entries_are_ignored():
    other = {"group_id": "x", "artifact_id": "y", "version": "9"}
    out = aggregate_reachability([entry("confirmed", dep=other)], DEP, ["v1"])
    assert out["status"] == "error"


def test_unknown_status_counts_as_error():
    assert aggregate_reachability([entry("weird")], DEP, ["v1"])["status"] == "error"


def test_load_reachability_missing_file_is_empty(tmp_path):
    assert load_reachability(tmp_path / "nope.json") == []


# ---- full report on synthetic data -------------------------------------

def _alert(vulns):
    return {"dependency": DEP, "vulnerabilities": vulns}


def test_report_flags_missing_environment_slot():
    alert = _alert([{"id": "v1", "in_kev": False, "epss_score": 0.1, "fixed_version_hint": "2"}])
    env = {k: v for k, v in ENV.items() if k != "asset_criticality"}
    rep = dependency_slot_report(alert, [entry("confirmed")], env)
    assert rep["needs_escalation"]
    assert rep["unresolved"] == ["asset_criticality"]


def test_report_is_json_serialisable():
    alert = _alert([{"id": "v1", "in_kev": False, "epss_score": None, "fixed_version_hint": None}])
    rep = dependency_slot_report(alert, [], ENV)
    json.dumps(rep)
    assert rep["unresolved"][:3] == ["reachability", "exploitation_status", "fix_availability"]


# ---- the real spike data -----------------------------------------------

ALERTS = ROOT / "results" / "alerts.json"
STUB = ROOT / "results" / "reachability.json"


@pytest.mark.skipif(not (ALERTS.exists() and STUB.exists()), reason="needs results/ data")
def test_spike_data_only_log4j_needs_escalation_with_full_environment():
    alerts = json.loads(ALERTS.read_text())
    results = load_reachability(STUB)
    escalating = {
        a["dependency"]["artifact_id"]
        for a in alerts
        if dependency_slot_report(a, results, ENV)["needs_escalation"]
    }
    assert escalating == {"log4j-core"}  # ambiguous reachability in the manual stub


@pytest.mark.skipif(not (ALERTS.exists() and STUB.exists()), reason="needs results/ data")
def test_spike_data_coverage_counts_are_reported():
    alerts = {a["dependency"]["artifact_id"]: a for a in json.loads(ALERTS.read_text())}
    results = load_reachability(STUB)
    rep = dependency_slot_report(alerts["jackson-core"], results, ENV)
    cov = rep["coverage"]["exploitation"]
    assert cov["vulnerabilities"] == 3 and cov["with_epss"] == 2  # one EPSS is null, still resolved
    assert rep["slots"]["exploitation_status"]["state"] == "resolved"