"""One study case, end to end, for either condition.

  micro     agent investigates -> slot check -> fixed-template questions (capped)
            -> agent resumes with the answers -> final verdict (agent)
  baseline  agent investigates -> slot check -> agent "stops" and dumps its
            transcript -> the analyst decides the verdict alone

Timing keeps system wait (agent/API/rate-limit) apart from analyst active time.
The engine and channel are injected, so this module has no LangChain or I/O
dependency and is fully testable.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence

from .dump import format_context_dump
from .questions import UNKNOWN, Question, build_question
from .report import dependency_slot_report
from .scenarios import Scenario
from .slots import Slot
from .verdict import score_verdict

CONDITIONS = ("micro", "baseline")


@dataclass
class Investigation:
    verdict: Dict[str, Any]
    messages: List[Any]
    duration_s: float = 0.0
    rate_limit_wait_s: float = 0.0
    models_used: List[str] = field(default_factory=list)


class Engine(Protocol):
    def investigate(self, alert: Mapping[str, Any], environment: Mapping[str, Any]) -> Investigation: ...
    def resume(self, messages: Sequence[Any], human_text: str) -> Investigation: ...


def count_tool_problems(messages: Sequence[Any]) -> int:
    """Tool calls that failed or found nothing because of bad arguments. Recorded so
    a run whose evidence was silently incomplete can be spotted in the analysis."""
    n = 0
    for m in messages:
        if getattr(m, "type", "") == "tool":
            if getattr(m, "status", None) == "error" or str(getattr(m, "content", "")).startswith("unknown —"):
                n += 1
    return n


def build_resume_message(qa: Sequence[tuple]) -> str:
    lines = ["The analyst has answered your outstanding questions:"]
    for q, a in qa:
        shown = a if a != UNKNOWN else "unknown (the analyst could not determine this)"
        lines.append(f"- {q.text}\n  Answer: {shown}")
    lines.append(
        "\nTreat these answers as verified facts. Do not repeat tool calls whose "
        "results you already have. Update your investigation where they matter and "
        "give your final verdict."
    )
    return "\n".join(lines)


def run_session(
    *,
    scenario: Scenario,
    alert: Mapping[str, Any],
    assets: Mapping[str, Mapping[str, Any]],
    reachability_results: Sequence[Mapping[str, Any]],
    condition: str,
    engine: Engine,
    channel: Any,
    participant_id: str,
    max_questions: int = 2,
    gate_environment_on_absent: bool = False,
    clock: Callable[[], float] = time.monotonic,
) -> Dict[str, Any]:
    if condition not in CONDITIONS:
        raise ValueError(f"condition must be one of {CONDITIONS}, got {condition!r}")

    started_at = datetime.now(timezone.utc).isoformat()
    t_start = clock()
    analyst_s = 0.0
    system_s = 0.0
    rate_wait_s = 0.0

    environment = scenario.environment(assets)
    channel.briefing(scenario.id, scenario.fact_sheet(assets))

    first = engine.investigate(alert, environment)
    system_s += first.duration_s
    rate_wait_s += first.rate_limit_wait_s

    report = dependency_slot_report(alert, reachability_results, environment, gate_environment_on_absent)
    unresolved = list(report["unresolved"])
    expected = set(scenario.expected_slots)
    design_check = {
        "expected_but_resolved": sorted(expected - set(unresolved)),
        "unexpected_unresolved": sorted(set(unresolved) - expected),
    }

    asked: List[Dict[str, Any]] = []
    skipped: List[str] = []
    final_verdict: Dict[str, Any]
    decided_by: str
    resumed: Optional[Investigation] = None
    dump: Optional[str] = None

    if not unresolved:
        final_verdict, decided_by = first.verdict, "agent_no_escalation"

    elif condition == "micro":
        qa = []
        for slot_value in unresolved[:max_questions]:
            q = build_question(Slot(slot_value), dependency=scenario.dependency, asset=scenario.asset_id)
            t0 = clock()
            answer = channel.ask(q)
            dt = clock() - t0
            analyst_s += dt
            qa.append((q, answer))
            asked.append({
                "slot": slot_value, "question": q.text,
                "choices": list(q.choices) if q.choices else None,
                "answer": answer, "analyst_seconds": round(dt, 3),
            })
        skipped = unresolved[max_questions:]
        resumed = engine.resume(first.messages, build_resume_message(qa))
        system_s += resumed.duration_s
        rate_wait_s += resumed.rate_limit_wait_s
        final_verdict, decided_by = resumed.verdict, "agent_after_escalation"

    else:  # baseline: the agent stops and hands over a raw transcript
        dump = format_context_dump(first.messages)
        t0 = clock()
        final_verdict = dict(channel.collect_verdict(dump))
        analyst_s += clock() - t0
        decided_by = "analyst"

    asked_slots = [a["slot"] for a in asked]
    answered_known = [a["slot"] for a in asked if a["answer"] != UNKNOWN]
    return {
        "scenario_id": scenario.id,
        "condition": condition,
        "participant_id": participant_id,
        "started_at": started_at,
        "asset_id": scenario.asset_id,
        "dependency": scenario.dependency,
        "withheld": list(scenario.withheld),
        "max_questions": max_questions,
        "first_pass": {
            "verdict": first.verdict,
            "models_used": first.models_used,
            "duration_s": round(first.duration_s, 3),
            "tool_problems": count_tool_problems(first.messages),
        },
        "slot_report_before": report,
        "design_check": design_check,
        "escalation": {
            "triggered": bool(unresolved),
            "unresolved": unresolved,
            "questions": asked,
            "skipped_due_to_cap": skipped,
            "unexpected_questions": [s for s in asked_slots if s not in expected],
            "still_unresolved_after": [s for s in unresolved if s not in answered_known],
        },
        "final": {"decided_by": decided_by, "verdict": final_verdict},
        "dump": dump,  # baseline only: exactly what the analyst was shown
        "resume_tool_problems": (
            None if resumed is None
            else count_tool_problems(resumed.messages) - count_tool_problems(first.messages)
        ),
        "resumed_verdict_changed": (
            None if resumed is None else resumed.verdict != first.verdict
        ),
        "score": score_verdict(final_verdict, scenario.expected),
        "first_pass_score": score_verdict(first.verdict, scenario.expected),
        "timing": {
            "analyst_active_s": round(analyst_s, 3),
            "system_wait_s": round(system_s, 3),
            "rate_limit_wait_s": round(rate_wait_s, 3),
            "total_s": round(clock() - t_start, 3),
        },
    }