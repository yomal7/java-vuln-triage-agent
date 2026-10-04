import json
from pathlib import Path

import pytest

from protocol.channels import ConsoleChannel
from protocol.dump import format_context_dump
from protocol.environment import load_assets
from protocol.questions import UNKNOWN, build_question
from protocol.scenarios import Scenario, load_scenarios, validate_scenarios
from protocol.slots import Slot
from protocol.verdict import TriageVerdict, score_verdict

ROOT = Path(__file__).resolve().parent.parent.parent
DATA = ROOT / "protocol" / "data"
ALERTS = ROOT / "results" / "alerts.json"


def test_every_slot_has_a_fixed_template_question():
    for slot in Slot:
        q = build_question(slot, dependency="g:a:1", asset="app")
        assert "{" not in q.text and q.text.endswith("?")
        if q.choices:
            assert UNKNOWN in q.choices


def test_same_slot_gives_identical_wording():
    a = build_question(Slot.NETWORK_EXPOSURE, dependency="d", asset="x")
    b = build_question(Slot.NETWORK_EXPOSURE, dependency="d", asset="x")
    assert a == b


@pytest.mark.skipif(not ALERTS.exists(), reason="needs results/alerts.json")
def test_example_scenarios_are_valid_against_real_alerts():
    import json as _j
    coords = [f"{a['dependency']['group_id']}:{a['dependency']['artifact_id']}:{a['dependency']['version']}"
              for a in _j.loads(ALERTS.read_text())]
    problems = validate_scenarios(load_scenarios(DATA / "scenarios.example.json"),
                                  load_assets(DATA / "environment.example.json"), coords)
    assert problems == []


def test_validation_reports_every_kind_of_mistake():
    assets = {"app": {"network_exposure": "internal"}}
    bad = [
        Scenario(id="A", asset_id="nope", dependency="x:y:1"),
        Scenario(id="A", asset_id="app", dependency="g:a:1", withheld=("patch_window",)),
        Scenario(id="B", asset_id="app", dependency="g:a:1", withheld=("typo_field",)),
        Scenario(id="C", asset_id="app", dependency="g:a:1", expected={"reachable": "Maybe"}),
        Scenario(id="D", asset_id="app", dependency="g:a:1", expected_slots=("nonsense",)),
        Scenario(id="E", asset_id="app", dependency="g:a:1", analyst_answers={"network_exposure": "internal"}),
        Scenario(id="F", asset_id="app", dependency="g:a:1", analyst_answers={"reachability": "perhaps"}),
    ]
    text = "\n".join(validate_scenarios(bad, assets, ["g:a:1"]))
    for needle in ["duplicate id", "unknown asset", "dependency 'x:y:1' not found", "has no 'patch_window'",
                   "not an environment field", "not an allowed option", "unknown slot",
                   "must be a tool slot", "is not one of"]:
        assert needle in text, needle


def test_fact_sheet_shows_the_truth_but_the_agent_view_does_not():
    assets = load_assets(DATA / "environment.example.json")
    sc = Scenario(id="S", asset_id="mock-app-01", dependency="x", withheld=("network_exposure",),
                  analyst_answers={"reachability": "yes"})
    assert sc.fact_sheet(assets)["known_facts"]["network_exposure"] == "internet_facing"
    assert "network_exposure" not in sc.environment(assets)
    assert sc.answer_for(Slot.NETWORK_EXPOSURE, assets) == "internet_facing"
    assert sc.answer_for(Slot.REACHABILITY, assets) == "yes"


# ---- verdict schema -----------------------------------------------------

GOOD = {"severity": "High", "reachable": "No", "reachable_justification": "x", "actively_exploited": False,
        "recommended_action": "Mitigate", "rationale": "r"}


def test_verdict_accepts_only_allowed_options():
    TriageVerdict(**GOOD)
    for field, bad in [("severity", "Severe"), ("reachable", "Maybe"), ("recommended_action", "Patch it")]:
        with pytest.raises(Exception):
            TriageVerdict(**{**GOOD, field: bad})


def test_score_only_checks_fields_the_scenario_defines():
    assert score_verdict(GOOD, {"reachable": "No"}) == {"reachable_correct": True, "exact": True}
    assert score_verdict(GOOD, {"reachable": "Yes", "recommended_action": "Mitigate"})["exact"] is False
    assert score_verdict(GOOD, {})["exact"] is None


# ---- dump + console -----------------------------------------------------

def test_dump_truncates_long_messages():
    class M:
        type, name, tool_calls = "human", None, []
        content = "x" * 5000
    out = format_context_dump([M()], max_chars=100)
    assert "truncated 4900 chars" in out


def test_console_channel_accepts_numbers_and_names_and_rejects_garbage():
    answers = iter(["9", "banana", "2", "internal"])
    out = []
    ch = ConsoleChannel(input_fn=lambda _: next(answers), print_fn=lambda *a: out.append(" ".join(map(str, a))))
    q = build_question(Slot.NETWORK_EXPOSURE, dependency="d", asset="app")
    assert ch.ask(q) == "internal"            # "2" -> second option
    assert ch.ask(q) == "internal"            # typed name
    assert sum("Please enter one of" in line for line in out) == 2


def test_dump_hides_verdicts_in_the_shapes_real_models_return():
    """Gemini returns the final verdict as raw JSON, fenced JSON, or a list of text parts."""
    class M:
        def __init__(self, content): self.type, self.content, self.tool_calls, self.name = "ai", content, [], None
    verdict = json.dumps({"severity": "High", "recommended_action": "Mitigate"})
    for content in (verdict, f"```json\n{verdict}\n```", [{"type": "text", "text": verdict}]):
        out = format_context_dump([M("I checked the tools."), M(content)])
        assert "I checked the tools." in out
        assert "recommended_action" not in out and "Mitigate" not in out