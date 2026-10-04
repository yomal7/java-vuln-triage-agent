"""How the analyst talks to the system: a scripted stand-in for development and
tests, and a terminal interface for real participants."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .questions import UNKNOWN, Question
from .verdict import ACTIONS, REACHABLE_OPTIONS, SEVERITIES


class ScriptedChannel:
    """Answers from a dict {slot value: answer}; anything missing is "unknown"."""

    def __init__(self, answers: Mapping[str, str], verdict: Optional[Mapping[str, str]] = None):
        self.answers = dict(answers)
        self.verdict = dict(verdict) if verdict else {
            "severity": "Medium", "reachable": "Unclear", "recommended_action": "Needs human review",
        }
        self.asked: List[Question] = []
        self.briefings: List[Dict[str, Any]] = []
        self.dumps: List[str] = []

    def briefing(self, scenario_id: str, fact_sheet: Mapping[str, Any]) -> None:
        self.briefings.append({"scenario": scenario_id, "fact_sheet": dict(fact_sheet)})

    def ask(self, question: Question) -> str:
        self.asked.append(question)
        return self.answers.get(question.slot.value, UNKNOWN)

    def collect_verdict(self, dump: str) -> Dict[str, str]:
        self.dumps.append(dump)
        return dict(self.verdict)


class ConsoleChannel:
    """Terminal interface for participants."""

    def __init__(self, input_fn: Callable[[str], str] = input, print_fn: Callable[..., None] = print):
        self._input = input_fn
        self._print = print_fn

    def briefing(self, scenario_id: str, fact_sheet: Mapping[str, Any]) -> None:
        p = self._print
        p("\n" + "=" * 70)
        p(f"CASE {scenario_id}  -  your fact sheet for {fact_sheet['asset']}")
        p("=" * 70)
        if fact_sheet.get("description"):
            p(fact_sheet["description"])
        for k, v in fact_sheet["known_facts"].items():
            p(f"  {k}: {v}")
        for k, v in fact_sheet["analyst_knowledge"].items():
            p(f"  you know ({k}): {v}")
        p("")

    def _choose(self, prompt: str, options: Sequence[str]) -> str:
        while True:
            self._print(prompt)
            for i, o in enumerate(options, 1):
                self._print(f"  {i}) {o}")
            raw = self._input("> ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return options[int(raw) - 1]
            if raw in options:
                return raw
            self._print("Please enter one of the numbers or option names above.\n")

    def ask(self, question: Question) -> str:
        self._print("\n--- The agent needs your help ---")
        if question.choices:
            return self._choose(question.text, question.choices)
        while True:
            self._print(question.text)
            raw = self._input("> ").strip()
            if question.accepts(raw):
                return raw
            self._print("An answer is required.\n")

    def collect_verdict(self, dump: str) -> Dict[str, str]:
        self._print("\n" + dump)
        self._print("\n--- Your verdict ---")
        return {
            "severity": self._choose("Severity?", SEVERITIES),
            "reachable": self._choose("Is the vulnerable functionality reachable?", REACHABLE_OPTIONS),
            "recommended_action": self._choose("Recommended action?", ACTIONS),
        }
