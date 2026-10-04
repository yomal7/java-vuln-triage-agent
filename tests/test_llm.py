import threading
import time

import pytest
from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_google_genai.chat_models import ChatGoogleGenerativeAIError

from llm import LLMConfig, RateLimiter, build_llm_stack, is_transient


# ---- helpers ------------------------------------------------------------

class ScriptedModel(BaseChatModel):
    """Plays back a script: an Exception is raised, a string is returned."""

    name: str
    script: list
    calls: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.calls += 1
        item = self.script[min(self.calls - 1, len(self.script) - 1)]
        if isinstance(item, Exception):
            raise item
        msg = AIMessage(content=item, response_metadata={"model_name": self.name})
        return ChatResult(generations=[ChatGeneration(message=msg)])

    @property
    def _llm_type(self) -> str:
        return "scripted"


class FakeHTTPError(Exception):
    """Stands in for google.genai.errors.APIError: carries an HTTP status in .code."""

    def __init__(self, code, msg=""):
        self.code = code
        super().__init__(f"{code} {msg}")


def wrapped_error(code, msg=""):
    """A 4xx the way langchain-google-genai surfaces it: a generic wrapper error
    whose __cause__ holds the HTTP status. Works on old and new library versions."""
    try:
        raise ChatGoogleGenerativeAIError(f"Error calling model ({code}): {msg}") from FakeHTTPError(code, msg)
    except ChatGoogleGenerativeAIError as e:
        return e


def rate_limited():
    return wrapped_error(429, "RESOURCE_EXHAUSTED")


def unavailable():
    return FakeHTTPError(503, "UNAVAILABLE")  # 5xx can surface unwrapped


def run(models, **cfg_overrides):
    cfg = LLMConfig(
        models=[m.name for m in models],
        rpm=1000,
        max_retries=cfg_overrides.pop("max_retries", 3),
        backoff_initial=2.0,
        backoff_factor=2.0,
        backoff_max=60.0,
        **cfg_overrides,
    )
    by_name = {m.name: m for m in models}
    stack = build_llm_stack(cfg, model_factory=lambda p, n, c: by_name[n])
    agent = create_agent(model=stack.model, tools=[], middleware=stack.middleware)
    out = agent.invoke({"messages": [("user", "hi")]})
    return out["messages"][-1], stack


@pytest.fixture
def sleeps(monkeypatch):
    """Record backoff sleeps instead of actually waiting."""
    recorded = []
    monkeypatch.setattr(time, "sleep", lambda s: recorded.append(s))
    return recorded


# ---- error classification ----------------------------------------------

@pytest.mark.parametrize("exc", [rate_limited(), unavailable(), TimeoutError(), ConnectionError()])
def test_transient_errors_are_retryable(exc):
    assert is_transient(exc)


def test_408_wrapped_error_is_retryable():
    assert is_transient(wrapped_error(408, "request timeout"))


@pytest.mark.parametrize(
    "exc",
    [
        wrapped_error(400, "bad request"),
        wrapped_error(401, "bad key"),
        wrapped_error(404, "no such model"),
        ValueError("bug"),
    ],
)
def test_permanent_errors_are_not_retryable(exc):
    assert not is_transient(exc)


# ---- retry with exponential backoff -------------------------------------

def test_retries_429_then_succeeds_with_growing_backoff(sleeps):
    primary = ScriptedModel(name="m1", script=[rate_limited(), rate_limited(), "ok"])
    reply, _ = run([primary])
    assert reply.content == "ok"
    assert primary.calls == 3
    assert len(sleeps) == 2
    # jitter is +-25%, so the second wait must clearly exceed the first
    assert 1.5 <= sleeps[0] <= 2.5
    assert 3.0 <= sleeps[1] <= 5.0


def test_retries_5xx(sleeps):
    primary = ScriptedModel(name="m1", script=[unavailable(), "ok"])
    reply, _ = run([primary])
    assert reply.content == "ok"
    assert primary.calls == 2


def test_does_not_retry_bad_request(sleeps):
    primary = ScriptedModel(name="m1", script=[wrapped_error(400, "bad")])
    with pytest.raises(ChatGoogleGenerativeAIError):
        run([primary])
    assert primary.calls == 1
    assert sleeps == []


# ---- fallback chain -----------------------------------------------------

def test_falls_back_after_retries_exhausted(sleeps):
    primary = ScriptedModel(name="m1", script=[rate_limited()])  # always 429
    backup = ScriptedModel(name="m2", script=["from backup"])
    reply, _ = run([primary, backup], max_retries=2)
    assert reply.content == "from backup"
    assert primary.calls == 3  # 1 try + 2 retries
    assert backup.calls == 1


def test_model_not_found_falls_back_without_retrying(sleeps):
    primary = ScriptedModel(name="m1", script=[wrapped_error(404, "no such model")])
    backup = ScriptedModel(name="m2", script=["ok"])
    reply, _ = run([primary, backup])
    assert reply.content == "ok"
    assert primary.calls == 1
    assert sleeps == []


def test_walks_the_whole_chain(sleeps):
    a = ScriptedModel(name="a", script=[rate_limited()])
    b = ScriptedModel(name="b", script=[unavailable()])
    c = ScriptedModel(name="c", script=["third"])
    reply, _ = run([a, b, c], max_retries=1)
    assert reply.content == "third"


def test_everything_failing_raises_instead_of_inventing_an_answer(sleeps):
    a = ScriptedModel(name="a", script=[rate_limited()])
    b = ScriptedModel(name="b", script=[rate_limited()])
    with pytest.raises(Exception) as info:
        run([a, b], max_retries=1)
    assert "429" in str(info.value)


# ---- requests-per-minute cap -------------------------------------------

class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def time(self):
        return self.now

    def sleep(self, s):
        self.slept.append(s)
        self.now += s


def test_limiter_blocks_the_call_over_the_cap():
    clock = FakeClock()
    lim = RateLimiter(3, period=60.0, clock=clock.time, sleep=clock.sleep)
    for _ in range(3):
        assert lim.acquire() == 0.0
    waited = lim.acquire()  # 4th call inside the same minute
    assert waited == pytest.approx(60.0)
    assert clock.slept == [pytest.approx(60.0)]


def test_limiter_window_slides():
    clock = FakeClock()
    lim = RateLimiter(2, period=60.0, clock=clock.time, sleep=clock.sleep)
    lim.acquire()
    clock.now = 30.0
    lim.acquire()
    clock.now = 61.0  # first call has aged out
    assert lim.acquire() == 0.0


def test_limiter_is_thread_safe_and_never_exceeds_cap():
    stamps = []
    lock = threading.Lock()
    lim = RateLimiter(5, period=0.5)

    def worker():
        lim.acquire()
        with lock:
            stamps.append(time.monotonic())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stamps.sort()
    # no 6 calls may fall inside one 0.5 s window
    for i in range(len(stamps) - 5):
        assert stamps[i + 5] - stamps[i] >= 0.49


def test_every_attempt_counts_against_the_cap(sleeps):
    primary = ScriptedModel(name="m1", script=[rate_limited(), "ok"])
    reply, stack = run([primary])
    assert reply.content == "ok"
    assert len(stack.rate_limit.limiter._calls) == 2  # the failed try + the retry


# ---- configuration ------------------------------------------------------

def test_config_reads_model_chain_and_limits(monkeypatch):
    monkeypatch.setenv("LLM_MODELS", " a-model , b-model ,c-model")
    monkeypatch.setenv("LLM_RPM", "7")
    monkeypatch.setenv("LLM_PROVIDER", "OpenAI")
    cfg = LLMConfig.from_env()
    assert cfg.models == ["a-model", "b-model", "c-model"]
    assert cfg.rpm == 7
    assert cfg.provider == "openai"


def test_config_falls_back_to_legacy_single_model(monkeypatch):
    monkeypatch.delenv("LLM_MODELS", raising=False)
    monkeypatch.setenv("GEMINI_MODEL", "legacy-model")
    assert LLMConfig.from_env().models == ["legacy-model"]


def test_no_base_url_by_default(monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    assert LLMConfig.from_env().base_url is None