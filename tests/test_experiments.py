"""Scenario generator and experiment runner, driven by a fake engine (no LLM)."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "results" / "alerts.json"
STUB = ROOT / "results" / "reachability.json"
pytestmark = pytest.mark.skipif(not (ALERTS.exists() and STUB.exists()), reason="needs results/ data")


def load():
    import generate_scenarios as gs
    from protocol.aggregate import load_reachability
    from protocol.environment import load_assets
    alerts = json.loads(ALERTS.read_text())
    assets = load_assets(ROOT / "protocol" / "data" / "environment.example.json")
    reach = load_reachability(STUB)
    return gs, alerts, assets, reach


def test_generator_builds_a_valid_set_from_the_rubric():
    gs, alerts, assets, reach = load()
    from protocol.scenarios import validate_scenarios
    scs = gs.build(alerts, assets, reach)
    assert len(scs) == len(alerts) * len(assets) * len(gs.PATTERNS)
    assert validate_scenarios(scs, assets, [gs.coord(a["dependency"]) for a in alerts]) == []
    by = {(s.dependency.split(":")[1], s.asset_id, s.withheld): s for s in scs}
    assert by[("log4j-core", "mock-app-01", ())].expected["recommended_action"] == "Upgrade immediately"
    assert by[("log4j-core", "mock-app-01", ())].expected_slots == ("reachability",)
    assert by[("junit", "mock-app-02", ())].expected["recommended_action"] == "Accept risk"
    assert by[("spring-core", "mock-app-01", ("network_exposure",))].expected_slots == ("network_exposure",)
    assert by[("spring-core", "mock-app-01", ())].expected_slots == ()          # a control


class FakeEngine:
    """Answers correctly only when it knows the exposure: makes the escalation effect visible."""
    def __init__(self, label=None, fail=False):
        self.fail = fail
        from protocol.session import Investigation
        self.I = Investigation

    class M:
        def __init__(self, t): self.type, self.content, self.tool_calls, self.name = t, "", [], None

    def investigate(self, alert, environment):
        if self.fail:
            raise RuntimeError("429 RESOURCE_EXHAUSTED")
        self.env = environment
        action = "Upgrade in next cycle"
        return self.I({"reachable": "No", "recommended_action": action}, [self.M("human"), self.M("ai")], 1.0)

    def resume(self, messages, text):
        return self.I({"reachable": "Yes", "recommended_action": "Upgrade immediately"},
                      list(messages) + [self.M("human"), self.M("ai")], 0.5)


def test_runner_records_both_conditions_and_is_resumable(tmp_path):
    import run_experiments as rx
    gs, alerts, assets, reach = load()
    scs = gs.build(alerts, assets, reach)[:3]
    by_coord = {gs.coord(a["dependency"]): a for a in alerts}
    kw = dict(alerts_by_coord=by_coord, assets=assets, reach=reach, reps=2, conditions=("micro", "full"),
              out_dir=tmp_path, engine_factory=lambda label: FakeEngine(label), log=lambda *a: None)
    first = rx.run_all(scs, **kw)
    assert first["done"] == 3 * 2 * 2 and first["failed"] == 0
    again = rx.run_all(scs, **kw)                       # nothing redone
    assert again["done"] == 0 and again["skipped"] == 12
    rec = json.loads((tmp_path / "records" / f"{scs[0].id}__micro__r1.json").read_text())
    assert rec["experiment_condition"] == "micro" and rec["expected"] and rec["first_pass"]["model_calls"] == 1


def test_full_info_variant_withholds_nothing_but_keeps_tool_gaps():
    import run_experiments as rx
    gs, alerts, assets, reach = load()
    log4j = next(s for s in gs.build(alerts, assets, reach) if "log4j" in s.dependency and s.withheld)
    full = rx.full_info_variant(log4j)
    assert full.withheld == () and full.expected_slots == ("reachability",)


def test_runner_stops_after_repeated_failures(tmp_path):
    import run_experiments as rx
    gs, alerts, assets, reach = load()
    scs = gs.build(alerts, assets, reach)[:10]
    by_coord = {gs.coord(a["dependency"]): a for a in alerts}
    out = rx.run_all(scs, alerts_by_coord=by_coord, assets=assets, reach=reach, reps=1, conditions=("micro",),
                     out_dir=tmp_path, engine_factory=lambda label: FakeEngine(label, fail=True),
                     stop_after_failures=3, log=lambda *a: None)
    assert out["stopped_early"] and out["failed"] == 3


def test_summary_tables(tmp_path):
    import run_experiments as rx
    gs, alerts, assets, reach = load()
    scs = gs.build(alerts, assets, reach)
    by_coord = {gs.coord(a["dependency"]): a for a in alerts}
    rx.run_all(scs, alerts_by_coord=by_coord, assets=assets, reach=reach, reps=2, conditions=("micro", "full"),
               out_dir=tmp_path, engine_factory=lambda label: FakeEngine(label), log=lambda *a: None)
    summary, md = rx.summarise(tmp_path)
    assert summary["records"] == len(scs) * 2 * 2
    assert summary["e2_trigger"]["designed_gap_missed"] == 0
    assert summary["e2_trigger"]["unnecessary_questions"] == 0
    assert summary["e2_trigger"]["control_cases_with_a_question"] == 0
    assert summary["majority_class"]["action"] == "Upgrade in next cycle"
    for header in ("E3: accuracy", "gap_no_escalation", "gap_micro", "full_info", "E2: escalation trigger", "Majority-class"):
        assert header in md
    assert (tmp_path / "summary.md").exists() and (tmp_path / "summary.json").exists()


def test_policy_reaches_the_agent_and_can_be_switched_off(monkeypatch):
    import triage_agent
    assert "Triage policy" in triage_agent.build_system_prompt("stored", True)
    assert "Triage policy" not in triage_agent.build_system_prompt("stored", False)
    monkeypatch.setenv("TRIAGE_POLICY", "off")
    assert triage_agent.policy_enabled() is False