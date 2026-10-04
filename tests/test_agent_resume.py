"""Real LangChain agent + real tools + real structured output, scripted model.
Proves that resume continues the SAME investigation (earlier tool calls/results
are in the history the model sees) and that the new verdict schema is enforced."""
import json
from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "results" / "alerts.json"
pytestmark = pytest.mark.skipif(not ALERTS.exists(), reason="run scanner/scan.py first")

FIRST = {"severity": "Medium", "reachable": "Unclear", "reachable_justification": "no env facts",
         "actively_exploited": False, "recommended_action": "Needs human review", "rationale": "first pass"}
FINAL = {"severity": "Critical", "reachable": "Yes", "reachable_justification": "analyst confirmed",
         "actively_exploited": False, "recommended_action": "Upgrade immediately", "rationale": "after answers"}


class Recorder(BaseChatModel):
    script: list
    seen: list = Field(default_factory=list)
    calls: int = 0

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.seen.append(list(messages))
        item = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1
        item = item.model_copy(update={"response_metadata": {"model_name": "scripted"}})
        return ChatResult(generations=[ChatGeneration(message=item)])

    @property
    def _llm_type(self):
        return "recorder"


def _call(name, args, id):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": id}])


def build(monkeypatch, tmp_path, script):
    import triage_agent
    from llm import LLMConfig, build_llm_stack

    model = Recorder(script=script)
    stack = build_llm_stack(LLMConfig(models=["scripted"], rpm=1000), model_factory=lambda p, n, c: model)
    monkeypatch.setattr(triage_agent, "build_llm_stack", lambda: stack)
    agent, stack = triage_agent.build_agent()
    return triage_agent, agent, stack, model


def alert(artifact="spring-core"):
    return next(a for a in json.loads(ALERTS.read_text()) if a["dependency"]["artifact_id"] == artifact)


def test_resume_keeps_the_whole_investigation_and_adds_the_answers(monkeypatch, tmp_path):
    ta, agent, stack, model = build(monkeypatch, tmp_path, [
        _call("check_reachability", {"group_id": "org.springframework", "artifact_id": "spring-core", "version": "5.2.0.RELEASE"}, "c1"),
        _call("TriageVerdict", FIRST, "c2"),
        _call("TriageVerdict", FINAL, "c3"),
    ])
    engine = ta.LangChainEngine(agent, stack, "S01_micro_P1", tmp_path / "logs")
    first = engine.investigate(alert(), {"asset_criticality": "high"})
    assert first.verdict["recommended_action"] == "Needs human review"
    assert first.models_used == ["scripted"]

    resumed = engine.resume(first.messages, "The analyst answered: network_exposure = internet_facing")
    assert resumed.verdict["recommended_action"] == "Upgrade immediately"

    last_input = model.seen[-1]
    kinds = [m.type for m in last_input]
    assert "tool" in kinds                                           # first-pass tool results are still there
    text = " ".join(str(m.content) for m in last_input)
    assert '"status": "absent"' in text                              # the check_reachability result
    assert "analyst answered" in text and "internet_facing" in text  # plus the new answers
    assert last_input[-1].type == "human"


def test_environment_facts_reach_the_agent_and_withheld_ones_do_not(monkeypatch, tmp_path):
    ta, agent, stack, model = build(monkeypatch, tmp_path, [_call("TriageVerdict", FIRST, "c1")])
    engine = ta.LangChainEngine(agent, stack, "S", tmp_path / "logs")
    engine.investigate(alert(), {"asset_criticality": "high", "patch_window": "monthly"})
    seed = str(model.seen[0][-1].content)
    assert "asset_criticality" in seed and "high" in seed
    assert "network_exposure" not in seed                            # withheld: the agent cannot see it
    assert "UNKNOWN to you" in seed


def test_the_old_batch_path_is_unchanged_without_environment(monkeypatch, tmp_path):
    ta, agent, stack, model = build(monkeypatch, tmp_path, [_call("TriageVerdict", FIRST, "c1")])
    monkeypatch.setattr(ta, "LLM_LOG_DIR", tmp_path)
    run = ta.triage_one(agent, alert(), stack.describe())
    assert run["verdict"]["severity"] == "Medium"
    assert "Environment facts" not in str(model.seen[0][-1].content)


def test_invalid_option_is_rejected_by_the_schema(monkeypatch, tmp_path):
    bad = {**FIRST, "recommended_action": "Patch it whenever"}
    ta, agent, stack, model = build(monkeypatch, tmp_path, [
        _call("TriageVerdict", bad, "c1"),       # invalid -> the framework retries
        _call("TriageVerdict", FIRST, "c2"),
    ])
    engine = ta.LangChainEngine(agent, stack, "S", tmp_path / "logs")
    out = engine.investigate(alert(), {})
    assert out.verdict["recommended_action"] == "Needs human review"
    assert model.calls == 2