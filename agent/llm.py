"""
llm.py — builds the chat model and the resilience layer around it.

What this gives the agent:
  * Direct provider calls (no gateway). The old localhost:8080 base_url is gone;
    set LLM_BASE_URL only if you deliberately want to route through one.
  * Retry with exponential backoff + jitter on transient errors only
    (HTTP 408, 429, 5xx, timeouts, connection errors). Auth errors, bad
    requests and unknown models are NOT retried — they fail fast.
  * A requests-per-minute cap (sliding window, shared by all threads), so the
    bounded concurrency in run_triage.py cannot burst past the quota.
  * A model fallback chain: if a model keeps failing after its retries
    (e.g. 429 daily quota, 404 model not available to your key), the next model
    in the chain is tried.
  * A swappable provider: change LLM_PROVIDER / LLM_MODELS in .env — no code
    change — when moving from the free tier to a paid API or another vendor.

Configuration (all optional, set in .env):
  LLM_PROVIDER      google (default) | openai | anthropic | any name accepted by
                    langchain's init_chat_model (needs that provider's package)
  LLM_MODELS        comma-separated chain, first = preferred. Example:
                    LLM_MODELS=gemini-3.7-flash,gemini-3.8-flash,gemini-3.5-flash-lite
                    (use `python agent/list_models.py` to see what your key can use)
  GEMINI_MODEL      legacy single-model setting; used only if LLM_MODELS is unset
  LLM_RPM           max model calls per minute across all threads (default 10)
  LLM_MAX_RETRIES   retries per model before falling back (default 3)
  LLM_BACKOFF_INITIAL / LLM_BACKOFF_FACTOR / LLM_BACKOFF_MAX
                    seconds / multiplier / cap (default 2 / 2 / 60)
  LLM_TIMEOUT       per-call timeout in seconds (default 60)
  LLM_TEMPERATURE   unset by default. Some models (e.g. flash-lite) ignore it and warn,
                    so runs are NOT guaranteed repeatable; record this as a limitation.
  LLM_BASE_URL      optional custom endpoint/gateway
  API keys          GOOGLE_API_KEY or GEMINI_API_KEY (google); the provider's
                    usual variable otherwise (OPENAI_API_KEY, ANTHROPIC_API_KEY)
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from langchain.agents.middleware import (
    AgentMiddleware,
    ModelFallbackMiddleware,
    ModelRetryMiddleware,
)

try:  # langchain-core >= 1.6 classifies provider errors; older versions don't have this
    from langchain_core.exceptions import ModelError
except ImportError:  # pragma: no cover - depends on the installed version
    ModelError = None  # type: ignore[assignment,misc]

DEFAULT_MODELS = ["gemini-3.5-flash-lite"]  # the model the spike already used


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


@dataclass
class LLMConfig:
    provider: str = "google"
    models: List[str] = field(default_factory=lambda: list(DEFAULT_MODELS))
    rpm: int = 10
    max_retries: int = 3
    backoff_initial: float = 2.0
    backoff_factor: float = 2.0
    backoff_max: float = 60.0
    timeout: float = 60.0
    temperature: Optional[float] = None  # None = provider default (some models ignore it)
    base_url: Optional[str] = None

    @classmethod
    def from_env(cls) -> "LLMConfig":
        raw_models = os.environ.get("LLM_MODELS") or os.environ.get("GEMINI_MODEL") or ""
        models = [m.strip() for m in raw_models.split(",") if m.strip()] or list(DEFAULT_MODELS)
        return cls(
            provider=(os.environ.get("LLM_PROVIDER") or "google").strip().lower(),
            models=models,
            rpm=_env_int("LLM_RPM", 10),
            max_retries=_env_int("LLM_MAX_RETRIES", 3),
            backoff_initial=_env_float("LLM_BACKOFF_INITIAL", 2.0),
            backoff_factor=_env_float("LLM_BACKOFF_FACTOR", 2.0),
            backoff_max=_env_float("LLM_BACKOFF_MAX", 60.0),
            timeout=_env_float("LLM_TIMEOUT", 60.0),
            temperature=_env_float("LLM_TEMPERATURE", 0.0) if os.environ.get("LLM_TEMPERATURE") else None,
            base_url=os.environ.get("LLM_BASE_URL") or None,
        )


# --------------------------------------------------------------------------
# Which errors are worth retrying?
# --------------------------------------------------------------------------

TRANSIENT_STATUS = {408, 429, 500, 502, 503, 504}


def _status_code(exc: BaseException) -> Optional[int]:
    """Find an HTTP status on the exception or anywhere in its cause chain."""
    seen = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        for attr in ("code", "status_code"):
            val = getattr(cur, attr, None)
            if isinstance(val, int):
                return val
        resp = getattr(cur, "response", None)
        val = getattr(resp, "status_code", None)
        if isinstance(val, int):
            return val
        cur = cur.__cause__ or cur.__context__
    return None


def is_transient(exc: Exception) -> bool:
    """True for errors where trying again (later) can succeed.

    Retry: 408, 429, 5xx, timeouts, connection problems.
    Do not retry: 400, 401, 403, 404, context overflow, programming errors —
    retrying cannot fix them, so they surface immediately (and the fallback
    chain, not the retry loop, handles e.g. a model your key cannot access).
    """
    if ModelError is not None and isinstance(exc, ModelError) and exc.is_retryable:
        return True
    status = _status_code(exc)
    if status is not None:
        return status in TRANSIENT_STATUS or 500 <= status < 600
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    name = type(exc).__name__.lower()
    return any(k in name for k in ("timeout", "connection", "ratelimit", "unavailable"))


# --------------------------------------------------------------------------
# Requests-per-minute cap
# --------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window limiter, safe to share between threads.

    acquire() blocks until a call is allowed and returns how long it waited
    (so callers can log wait time separately from analyst time).
    """

    def __init__(
        self,
        max_calls: int,
        period: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if max_calls < 1:
            raise ValueError("max_calls must be >= 1")
        self.max_calls = max_calls
        self.period = period
        self._clock = clock
        self._sleep = sleep
        self._calls: deque = deque()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        waited = 0.0
        while True:
            with self._lock:
                now = self._clock()
                while self._calls and now - self._calls[0] >= self.period:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return waited
                delay = self.period - (now - self._calls[0])
            delay = max(delay, 0.01)
            self._sleep(delay)
            waited += delay


class RateLimitMiddleware(AgentMiddleware):
    """Blocks each model call until the shared limiter allows it."""

    def __init__(self, limiter: RateLimiter):
        super().__init__()
        self.tools = []
        self.limiter = limiter
        self.total_wait_seconds = 0.0  # system wait time, kept apart from analyst time
        self._lock = threading.Lock()

    def wrap_model_call(self, request, handler):
        waited = self.limiter.acquire()
        if waited:
            with self._lock:
                self.total_wait_seconds += waited
        return handler(request)


# --------------------------------------------------------------------------
# Building the model chain
# --------------------------------------------------------------------------

def _make_model(provider: str, model: str, cfg: LLMConfig):
    """One chat model. max_retries is 0 on purpose: the middleware owns retries,
    so retries are not multiplied by the SDK's own retry loop."""
    if provider in ("google", "gemini", "google_genai"):
        from langchain_google_genai import ChatGoogleGenerativeAI

        api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "Set GOOGLE_API_KEY (or GEMINI_API_KEY) in .env — get a key from "
                "Google AI Studio."
            )
        kwargs: dict[str, Any] = dict(
            model=model,
            google_api_key=api_key,
            timeout=cfg.timeout,
            max_retries=0,
        )
        if cfg.temperature is not None:
            kwargs["temperature"] = cfg.temperature
        if cfg.base_url:
            kwargs["base_url"] = cfg.base_url
        return ChatGoogleGenerativeAI(**kwargs)

    # Any other provider via LangChain's universal initializer. Install the
    # matching package first (e.g. `uv add langchain-openai`).
    from langchain.chat_models import init_chat_model

    kwargs = dict(timeout=cfg.timeout, max_retries=0)
    if cfg.temperature is not None:
        kwargs["temperature"] = cfg.temperature
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    return init_chat_model(model, model_provider=provider, **kwargs)


@dataclass
class LLMStack:
    """Everything create_agent needs, plus handles for logging."""
    model: Any
    middleware: list
    config: LLMConfig
    rate_limit: RateLimitMiddleware

    def describe(self) -> dict:
        c = self.config
        return {
            "provider": c.provider,
            "models": c.models,
            "rpm": c.rpm,
            "max_retries": c.max_retries,
            "backoff": [c.backoff_initial, c.backoff_factor, c.backoff_max],
            "temperature": c.temperature,
            "timeout": c.timeout,
        }


def build_llm_stack(
    cfg: Optional[LLMConfig] = None,
    *,
    model_factory: Optional[Callable[[str, str, LLMConfig], Any]] = None,
    limiter: Optional[RateLimiter] = None,
    retry_on: Callable[[Exception], bool] = is_transient,
) -> LLMStack:
    """Primary model + middleware [fallback -> retry -> rate limit].

    The first middleware is the outermost: fallback wraps retry wraps the rate
    limiter wraps the real call. So every attempt (including each retry) is
    counted against the per-minute cap, and a model that exhausts its retries
    hands over to the next model in the chain.
    """
    cfg = cfg or LLMConfig.from_env()
    factory = model_factory or _make_model
    models = [factory(cfg.provider, name, cfg) for name in cfg.models]

    rate_limit = RateLimitMiddleware(limiter or RateLimiter(cfg.rpm))
    retry = ModelRetryMiddleware(
        max_retries=cfg.max_retries,
        retry_on=retry_on,
        on_failure="error",  # never turn an API failure into a fake "answer"
        backoff_factor=cfg.backoff_factor,
        initial_delay=cfg.backoff_initial,
        max_delay=cfg.backoff_max,
        jitter=True,
    )
    middleware: list = []
    if len(models) > 1:
        middleware.append(ModelFallbackMiddleware(*models[1:]))
    middleware += [retry, rate_limit]
    return LLMStack(model=models[0], middleware=middleware, config=cfg, rate_limit=rate_limit)
