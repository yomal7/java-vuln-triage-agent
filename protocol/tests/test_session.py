import json

import pytest

from protocol.channels import ScriptedChannel
from protocol.scenarios import Scenario
from protocol.session import Investigation, build_resume_message, run_session

DEP = {"group_id": "g", "artifact_id": "a", "version": "1"}
COORD = "g:a:1"
ALERT = {
    "dependency": DEP,
    "vulnerabilities": [{"id": "V1", "in_kev": False, "epss_score": 0.1, "fixed_version_hint": "2"}],
}
ASSETS = {
    "app": {
        "description": "Test app",
        "network_exposure": "internet_facing",
        "asset_criticality": "high",
        "patch_window": "monthly",
    }
}
REACH_OK = [{"dependency": DEP, "vulnerability_id": "*", "status": "confirmed"}]
REACH_AMBIGUOUS = [{"dependency": DEP, "vulnerability_id": "*", "status": "ambiguous"}]

FIRST = {"severity": "Medium", "reachable": "Unclear", "recommended_action": "Needs human review"}
FINAL = {"severity": "Critical", "reachable": "Yes", "recommended_action": "Upgrade immediately"}


class FakeMsg:
    def __init__(self, type, content, tool_calls=None, name=None):
        self.type, self.content, self.tool_calls, self.name = type, content, tool_calls or [], name


class FakeEngine:
    def __init__(self):
        self.calls = []
        self.first_messages = [
            FakeMsg("human", "Investigate g:a:1"),
            FakeMsg("ai", "", [{"name": "search_code_usage", "args": {"artifact_id": "a"}}]),
            FakeMsg("tool", "No references found", name="search_code_usage"),
            FakeMsg("ai", "", [{"name": "TriageVerdict", "args": FIRST}]),
            FakeMsg("tool", "ok", name="TriageVerdict"),
        ]

    def investigate(self, alert, environment):
        self.calls.append(("investigate", dict(environment)))
        return Investigation(dict(FIRST), self.first_messages, duration_s=2.0, rate_limit_wait_s=0.5, models_used=["m"])

    def resume(self, messages, human_text):
        self.calls.append(("resume", list(messages), human_text))
        return Investigation(dict(FINAL), list(messages), duration_s=1.5, rate_limit_wait_s=0.0)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class TimedChannel(ScriptedChannel):
    """Each question takes 7 simulated seconds to answer; the verdict takes 30."""

    def __init__(self, clock, *a, **k):
        super().__init__(*a, **k)
        self.clock = clock

    def ask(self, question):
        self.clock.advance(7)
        return super().ask(question)

    def collect_verdict(self, dump):
        self.clock.advance(30)
        return super().collect_verdict(dump)


def scenario(**over):
    base = dict(id="S", asset_id="app", dependency=COORD, withheld=("network_exposure",),
                expected={"reachable": "Yes", "recommended_action": "Upgrade immediately"},
                expected_slots=("network_exposure",))
    base.update(over)
    return Scenario(**base)


def run(cond, sc=None, reach=REACH_OK, answers=None, verdict=None, max_questions=2, engine=None, clock=None):
    clock = clock or Clock()
    engine = engine or FakeEngine()
    channel = TimedChannel(clock, answers if answers is not None else {"network_exposure": "internet_facing"}, verdict)
    rec = run_session(scenario=sc or scenario(), alert=ALERT, assets=ASSETS, reachability_results=reach,
                      condition=cond, engine=engine, channel=channel, participant_id="P1",
                      max_questions=max_questions, clock=clock)
    return rec, engine, channel


# ---- micro-escalation ---------------------------------------------------

def test_micro_asks_the_missing_fact_then_resumes_the_same_investigation():
    rec, engine, channel = run("micro")
    assert [q.slot.value for q in channel.asked] == ["network_exposure"]
    kind, messages, text = engine.calls[1]
    assert kind == "resume"
    assert messages == engine.first_messages          # same message objects: full prior state, not rebuilt
    assert "internet_facing" in text and "Is app reachable" in text
    assert rec["final"]["decided_by"] == "agent_after_escalation"
    assert rec["final"]["verdict"] == FINAL
    assert rec["score"] == {"reachable_correct": True, "recommended_action_correct": True, "exact": True}
    assert rec["first_pass_score"]["exact"] is False
    assert rec["resumed_verdict_changed"] is True


def test_agent_never_sees_the_withheld_fact():
    _, engine, _ = run("micro")
    assert "network_exposure" not in engine.calls[0][1]
    assert engine.calls[0][1]["asset_criticality"] == "high"


def test_question_cap_and_priority_order():
    sc = scenario(withheld=("network_exposure", "asset_criticality", "patch_window"),
                  expected_slots=("network_exposure", "asset_criticality", "patch_window"))
    rec, _, channel = run("micro", sc=sc, max_questions=2,
                          answers={"network_exposure": "internal", "asset_criticality": "low"})
    assert [q.slot.value for q in channel.asked] == ["network_exposure", "asset_criticality"]
    assert rec["escalation"]["skipped_due_to_cap"] == ["patch_window"]


def test_tool_slots_are_asked_before_environment_slots():
    sc = scenario(expected_slots=("reachability", "network_exposure"))
    rec, _, channel = run("micro", sc=sc, reach=REACH_AMBIGUOUS,
                          answers={"reachability": "yes", "network_exposure": "internal"})
    assert [q.slot.value for q in channel.asked] == ["reachability", "network_exposure"]
    assert rec["design_check"] == {"expected_but_resolved": [], "unexpected_unresolved": []}


def test_unknown_answer_is_recorded_and_slot_stays_unresolved():
    rec, _, _ = run("micro", answers={})  # scripted analyst says "unknown"
    assert rec["escalation"]["questions"][0]["answer"] == "unknown"
    assert rec["escalation"]["still_unresolved_after"] == ["network_exposure"]


def test_no_gap_means_no_question_in_either_condition():
    sc = scenario(withheld=(), expected_slots=())
    for cond in ("micro", "baseline"):
        rec, engine, channel = run(cond, sc=sc)
        assert channel.asked == [] and len(engine.calls) == 1
        assert rec["final"]["decided_by"] == "agent_no_escalation"
        assert rec["escalation"]["triggered"] is False


def test_unexpected_question_is_flagged():
    sc = scenario(expected_slots=())                    # gap exists but was not designed
    rec, _, _ = run("micro", sc=sc)
    assert rec["escalation"]["unexpected_questions"] == ["network_exposure"]
    assert rec["design_check"]["unexpected_unresolved"] == ["network_exposure"]


def test_design_check_catches_an_expected_slot_that_was_not_triggered():
    sc = scenario(expected_slots=("network_exposure", "patch_window"))
    rec, _, _ = run("micro", sc=sc)
    assert rec["design_check"]["expected_but_resolved"] == ["patch_window"]


# ---- baseline -----------------------------------------------------------

def test_baseline_stops_and_the_analyst_decides_from_a_dump_without_the_verdict():
    rec, engine, channel = run("baseline", verdict=FINAL)
    assert len(engine.calls) == 1                       # never resumed
    assert rec["final"]["decided_by"] == "analyst"
    assert rec["final"]["verdict"] == FINAL
    dump = channel.dumps[0]
    assert "INVESTIGATION STOPPED" in dump and "No references found" in dump
    assert "recommended_action" not in dump and "TriageVerdict" not in dump
    assert channel.asked == []
    assert rec["dump"] == dump                          # the record keeps exactly what the analyst saw


def test_micro_record_has_no_dump():
    rec, _, _ = run("micro")
    assert rec["dump"] is None


# ---- timing -------------------------------------------------------------

def test_timing_separates_analyst_time_from_system_wait():
    rec, _, _ = run("micro")
    t = rec["timing"]
    assert t["analyst_active_s"] == 7.0
    assert t["system_wait_s"] == 3.5                    # 2.0 first pass + 1.5 resume
    assert t["rate_limit_wait_s"] == 0.5
    rec, _, _ = run("baseline", verdict=FINAL)
    assert rec["timing"]["analyst_active_s"] == 30.0
    assert rec["timing"]["system_wait_s"] == 2.0


# ---- misc ---------------------------------------------------------------

def test_record_is_json_serialisable_and_bad_condition_rejected():
    rec, _, _ = run("micro")
    json.dumps(rec)
    with pytest.raises(ValueError):
        run("both")


def test_resume_message_marks_unknown_answers():
    from protocol.questions import build_question
    from protocol.slots import Slot
    q = build_question(Slot.NETWORK_EXPOSURE, dependency=COORD, asset="app")
    assert "could not determine" in build_resume_message([(q, "unknown")])