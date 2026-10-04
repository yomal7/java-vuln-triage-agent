"""Fixed-template escalation questions (one per slot).

The LLM never writes these: every participant gets identical wording, so the
question itself is not a confound. Choice questions keep answers measurable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from .slots import Slot

UNKNOWN = "unknown"


@dataclass(frozen=True)
class Question:
    slot: Slot
    text: str
    choices: Optional[Tuple[str, ...]] = None  # None = free text

    def accepts(self, answer: str) -> bool:
        if self.choices is None:
            return bool(answer and answer.strip())
        return answer in self.choices


_TEMPLATES = {
    Slot.REACHABILITY: (
        "Static analysis could not determine whether the vulnerable functionality of "
        "{dependency} is used by {asset}. Is it used in this deployment?",
        ("yes", "no", UNKNOWN),
    ),
    Slot.EXPLOITATION: (
        "No exploitation data was found for {dependency}. Has your team seen "
        "exploitation attempts against {asset}?",
        ("yes", "no", UNKNOWN),
    ),
    Slot.FIX_AVAILABILITY: (
        "No fixed version was identified for {dependency}. Is a vendor patch or an "
        "approved mitigation available?",
        ("patch_available", "workaround_only", "none", UNKNOWN),
    ),
    Slot.NETWORK_EXPOSURE: (
        "Is {asset} reachable from the internet or other untrusted networks?",
        ("internet_facing", "internal", "isolated", UNKNOWN),
    ),
    Slot.ASSET_CRITICALITY: (
        "What is the business criticality tier of {asset}?",
        ("low", "medium", "high", "critical", UNKNOWN),
    ),
    Slot.PATCH_WINDOW: (
        "When is the next patch window for {asset}?",
        None,
    ),
}


def allowed_answers(slot: Slot) -> Optional[Tuple[str, ...]]:
    return _TEMPLATES[slot][1]


def build_question(slot: Slot, *, dependency: str, asset: str) -> Question:
    text, choices = _TEMPLATES[slot]
    return Question(slot=slot, text=text.format(dependency=dependency, asset=asset), choices=choices)
