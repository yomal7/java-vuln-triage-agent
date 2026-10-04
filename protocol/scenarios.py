"""Scenarios: one study case = (alert, asset, hidden facts, expected verdict).

Each asset in the environment file holds the complete truth. A scenario hides
some of it from the agent (`withheld`), so the agent hits a gap that only the
analyst can fill. `expected` is the ground-truth verdict used to score accuracy.
`expected_slots` lists the slots the scenario is DESIGNED to leave unresolved,
so questions beyond them can be counted as unnecessary interruptions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from .environment import KNOWN_FIELDS, agent_view
from .questions import allowed_answers
from .slots import ENV_FIELD, ENVIRONMENT_SLOTS, TOOL_SLOTS, Slot
from .verdict import SCORED_FIELDS, VOCABULARY


@dataclass(frozen=True)
class Scenario:
    id: str
    asset_id: str
    dependency: str  # "group:artifact:version", matches an alert in alerts.json
    withheld: Tuple[str, ...] = ()
    expected: Mapping[str, str] = field(default_factory=dict)
    expected_slots: Tuple[str, ...] = ()
    analyst_answers: Mapping[str, str] = field(default_factory=dict)  # tool-slot answers
    notes: str = ""

    def environment(self, assets: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
        """What the agent is allowed to see."""
        return agent_view(assets[self.asset_id], self.withheld)

    def fact_sheet(self, assets: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
        """What the participant sees: the complete truth about the asset."""
        facts = assets[self.asset_id]
        return {
            "asset": self.asset_id,
            "description": facts.get("description", ""),
            "known_facts": {f: facts[f] for f in KNOWN_FIELDS if f in facts},
            "analyst_knowledge": dict(self.analyst_answers),
        }

    def answer_for(self, slot: Slot, assets: Mapping[str, Mapping[str, Any]]) -> Optional[str]:
        """The correct answer to a question about `slot` (used by simulated analysts)."""
        if slot in ENVIRONMENT_SLOTS:
            return assets[self.asset_id].get(ENV_FIELD[slot])
        return self.analyst_answers.get(slot.value)


def load_scenarios(path: Union[str, Path]) -> List[Scenario]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for raw in data["scenarios"]:
        raw = {k: v for k, v in raw.items() if not k.startswith("_")}
        out.append(
            Scenario(
                id=raw["id"],
                asset_id=raw["asset_id"],
                dependency=raw["dependency"],
                withheld=tuple(raw.get("withheld", ())),
                expected=dict(raw.get("expected", {})),
                expected_slots=tuple(raw.get("expected_slots", ())),
                analyst_answers=dict(raw.get("analyst_answers", {})),
                notes=raw.get("notes", ""),
            )
        )
    return out


def validate_scenarios(
    scenarios: Iterable[Scenario],
    assets: Mapping[str, Mapping[str, Any]],
    alert_coords: Iterable[str],
) -> List[str]:
    """Return a list of human-readable problems (empty list = data is clean)."""
    coords = set(alert_coords)
    slot_values = {s.value for s in Slot}
    tool_slot_values = {s.value for s in TOOL_SLOTS}
    problems: List[str] = []
    seen = set()
    for sc in scenarios:
        where = f"scenario {sc.id}"
        if sc.id in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(sc.id)
        if sc.asset_id not in assets:
            problems.append(f"{where}: unknown asset {sc.asset_id!r}")
        elif sc.withheld:
            for f in sc.withheld:
                if f not in KNOWN_FIELDS:
                    problems.append(f"{where}: withheld field {f!r} is not an environment field")
                elif f not in assets[sc.asset_id]:
                    problems.append(f"{where}: asset {sc.asset_id!r} has no {f!r} to withhold")
        if sc.dependency not in coords:
            problems.append(f"{where}: dependency {sc.dependency!r} not found in alerts.json")
        for f, v in sc.expected.items():
            if f not in SCORED_FIELDS:
                problems.append(f"{where}: expected field {f!r} is not scored")
            elif v not in VOCABULARY[f]:
                problems.append(f"{where}: expected {f}={v!r} is not an allowed option")
        for s in sc.expected_slots:
            if s not in slot_values:
                problems.append(f"{where}: expected_slots has unknown slot {s!r}")
        for s, a in sc.analyst_answers.items():
            if s not in tool_slot_values:
                problems.append(f"{where}: analyst_answers key {s!r} must be a tool slot")
                continue
            choices = allowed_answers(Slot(s))
            if choices is not None and a not in choices:
                problems.append(f"{where}: analyst answer {a!r} for {s} is not one of {list(choices)}")
    return problems


def check_scenarios(scenarios, assets, alert_coords) -> None:
    problems = validate_scenarios(scenarios, assets, alert_coords)
    if problems:
        raise ValueError("invalid scenario data:\n  - " + "\n  - ".join(problems))
