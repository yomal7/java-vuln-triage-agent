"""The CLI glue, driven by a fake engine (no LLM)."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "results" / "alerts.json"
pytestmark = pytest.mark.skipif(not ALERTS.exists(), reason="run scanner/scan.py first")


class FakeEngine:
    def __init__(self, label):
        from protocol.session import Investigation
        self.Investigation = Investigation

    def investigate(self, alert, environment):
        return self.Investigation({"severity": "Low", "reachable": "No", "recommended_action": "Accept risk"}, [], 1.0)

    def resume(self, messages, text):
        return self.Investigation({"severity": "High", "reachable": "Yes", "recommended_action": "Upgrade immediately"}, [], 1.0)


def load_all(args):
    from protocol.aggregate import load_reachability
    from protocol.environment import load_assets
    from protocol.scenarios import check_scenarios, load_scenarios
    sys.path.insert(0, str(ROOT / "agent"))
    import run_session as rs
    alerts = json.loads(ALERTS.read_text())
    by_coord = {rs._coord(a): a for a in alerts}
    assets = load_assets(rs.DEFAULT_ENVIRONMENT)
    scs = load_scenarios(rs.DEFAULT_SCENARIOS)
    check_scenarios(scs, assets, by_coord)
    return rs, by_coord, assets, scs, load_reachability(rs.DEFAULT_REACHABILITY)


def test_every_example_scenario_runs_in_both_conditions(tmp_path):
    rs, by_coord, assets, scs, reach = load_all(None)
    for sc in scs:
        for cond in ("micro", "baseline"):
            rec = rs.run_one(sc, alerts_by_coord=by_coord, assets=assets, reach=reach, condition=cond,
                             participant="SIM", simulate=True, max_questions=2, gate=False,
                             engine_factory=FakeEngine, out_dir=tmp_path)
            assert (tmp_path / f"{sc.id}_{cond}_SIM.json").exists()
            assert rec["design_check"] == {"expected_but_resolved": [], "unexpected_unresolved": []}, sc.id


def test_control_scenario_asks_nothing_and_gap_scenarios_ask_what_was_designed(tmp_path):
    rs, by_coord, assets, scs, reach = load_all(None)
    by_id = {s.id: s for s in scs}
    kw = dict(alerts_by_coord=by_coord, assets=assets, reach=reach, condition="micro", participant="SIM",
              simulate=True, max_questions=2, gate=False, engine_factory=FakeEngine, out_dir=tmp_path)
    assert rs.run_one(by_id["S03"], **kw)["escalation"]["questions"] == []
    q = rs.run_one(by_id["S01"], **kw)["escalation"]["questions"]
    assert [x["slot"] for x in q] == ["reachability", "network_exposure"]
    assert [x["answer"] for x in q] == ["yes", "internet_facing"]      # simulated analyst answers from the fact sheet