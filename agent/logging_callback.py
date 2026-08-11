"""
logging_callback.py — verbose progress printing + full LLM I/O logging.

Attach via config={"callbacks": [TriageLoggingCallback(...)]} on invoke().
Console output tells you the agent is alive; results/llm/<dependency>/ holds
the exact prompt sent and response received for every model call, plus
every tool call's input/output, for debugging when something looks wrong
or just seems to be taking a while.
"""
import json
import time
from pathlib import Path
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import BaseMessage


def _message_to_dict(msg: BaseMessage) -> dict:
    return {"type": msg.type, "content": msg.content}


class TriageLoggingCallback(BaseCallbackHandler):
    """Create one instance per dependency being triaged."""

    def __init__(self, label: str, log_dir: Path):
        self.label = label
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._step = 0
        self._start_times: dict[UUID, float] = {}

    def _write(self, name: str, payload: dict):
        path = self.log_dir / f"{self._step:03d}_{name}.json"
        path.write_text(json.dumps(payload, indent=2, default=str))

    # --- model calls ---------------------------------------------------
    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
        self._start_times[run_id] = time.monotonic()
        self._step += 1
        flat = [m for batch in messages for m in batch]
        print(f"  [{self.label}] step {self._step}: -> sending {len(flat)} message(s) to model ...", flush=True)
        self._write("llm_request", {"messages": [_message_to_dict(m) for m in flat]})

    def on_llm_end(self, response, *, run_id, **kwargs):
        elapsed = time.monotonic() - self._start_times.pop(run_id, time.monotonic())
        text_out, tool_calls = "", []
        try:
            msg = response.generations[0][0].message
            text_out = msg.content if isinstance(msg.content, str) else str(msg.content)
            tool_calls = getattr(msg, "tool_calls", []) or []
        except Exception:
            pass
        summary = f"{len(text_out)} chars"
        if tool_calls:
            summary += ", tool call(s): " + ", ".join(tc.get("name", "?") for tc in tool_calls)
        print(f"  [{self.label}] <- model responded in {elapsed:.1f}s ({summary})", flush=True)
        self._write(
            "llm_response",
            {"elapsed_seconds": round(elapsed, 2), "content": text_out, "tool_calls": tool_calls},
        )

    def on_llm_error(self, error, *, run_id, **kwargs):
        elapsed = time.monotonic() - self._start_times.pop(run_id, time.monotonic())
        print(f"  [{self.label}] XX model call failed after {elapsed:.1f}s: {error}", flush=True)
        self._write("llm_error", {"elapsed_seconds": round(elapsed, 2), "error": str(error)})

    # --- tool calls ------------------------------------------------------
    def on_tool_start(self, serialized, input_str, *, run_id, metadata=None, inputs=None, **kwargs):
        self._start_times[run_id] = time.monotonic()
        self._step += 1
        name = serialized.get("name", "tool")
        args = inputs if inputs is not None else input_str
        print(f"  [{self.label}] step {self._step}: -- calling {name}({args})", flush=True)
        self._write(f"tool_call_{name}", {"name": name, "input": args})

    def on_tool_end(self, output, *, run_id, **kwargs):
        elapsed = time.monotonic() - self._start_times.pop(run_id, time.monotonic())
        text = str(output)
        preview = text[:200] + ("..." if len(text) > 200 else "")
        print(f"  [{self.label}] ok tool returned in {elapsed:.1f}s: {preview}", flush=True)
        self._write("tool_result", {"elapsed_seconds": round(elapsed, 2), "output": text})

    def on_tool_error(self, error, *, run_id, **kwargs):
        elapsed = time.monotonic() - self._start_times.pop(run_id, time.monotonic())
        print(f"  [{self.label}] XX tool failed after {elapsed:.1f}s: {error}", flush=True)
        self._write("tool_error", {"elapsed_seconds": round(elapsed, 2), "error": str(error)})
