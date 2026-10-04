"""End-to-end wiring check: real create_agent + real tools + structured verdict +
retry/fallback middleware, with a scripted model standing in for the API."""
import json
from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_google_genai.chat_models import ChatGoogleGenerativeAIError

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "results" / "alerts.json"
pytestmark = pytest.mark.skipif(not ALERTS.exists(), reason="run scanner/scan.py first")

VERDICT = {
    "severity": "Low",
    "reachable": "No",
    "reachable_justification": "nothing in source",
    "actively_exploited": False,
    "epss_score": "0.01",
    "recommended_action": "Upgrade in next cycle",
    "fixed_version": "1.0.0",
    "rationale": "Scripted verdict for the wiring test.",
}


class ToolScriptedModel(BaseChatModel):
    name: str
    script: list
    calls: int = 0

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.calls += 1
        item = self.script[min(self.calls - 1, len(self.script) - 1)]
        if isinstance(item, Exception):
            raise item
        item = item.model_copy(update={"response_metadata": {"model_name": self.name}})
        return ChatResult(generations=[ChatGeneration(message=item)])

    @property
    def _llm_type(self):
        return "tool-scripted"


class _HTTP429(Exception):
    code = 429


def _rate_limited():
    try:
        raise ChatGoogleGenerativeAIError("Error calling model (429): RESOURCE_EXHAUSTED") from _HTTP429("429")
    except ChatGoogleGenerativeAIError as e:
        return e


def _script():
    return [
        _rate_limited(),  # first call fails, then retries
        AIMessage(content="", tool_calls=[
            {"name": "check_reachability", "args": {"group_id": "com.fasterxml.jackson.core", "artifact_id": "jackson-databind", "version": "2.9.8"}, "id": "c1"}]),
        AIMessage(content="", tool_calls=[
            {"name": "TriageVerdict", "args": VERDICT, "id": "c2"}]),
    ]


def test_full_triage_run_survives_a_429_and_records_llm_settings(tmp_path, monkeypatch):
    import time

    import triage_agent
    from llm import LLMConfig, build_llm_stack

    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setattr(triage_agent, "LLM_LOG_DIR", tmp_path)

    model = ToolScriptedModel(name="scripted-model", script=_script())
    cfg = LLMConfig(models=["scripted-model"], rpm=1000)
    stack = build_llm_stack(cfg, model_factory=lambda p, n, c: model)
    monkeypatch.setattr(triage_agent, "build_llm_stack", lambda: stack)

    agent, stack = triage_agent.build_agent()
    alert = json.loads(ALERTS.read_text())[0]
    run = triage_agent.triage_one(agent, alert, stack.describe())

    assert run["verdict"]["severity"] == "Low"
    assert run["llm"]["models_used"] == ["scripted-model"]
    assert run["llm"]["rpm"] == 1000
    assert model.calls == 3  # 429, tool call, final verdict
    assert any(m["type"] == "tool" for m in run["trace"])