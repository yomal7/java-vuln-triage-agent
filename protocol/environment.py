"""Mock environment: one complete record per asset, masked per scenario.

Each asset holds the full truth (this is what the participant's fact sheet shows).
A scenario lists the fields it withholds; the agent only ever sees the masked
view, so a withheld field is exactly what triggers a micro-escalation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Union

from .slots import ENV_FIELD

KNOWN_FIELDS = tuple(ENV_FIELD.values())


def load_assets(path: Union[str, Path]) -> Dict[str, Dict[str, Any]]:
    """Return {asset_id: facts} from an environment JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data["assets"]


def agent_view(facts: Mapping[str, Any], withheld: Iterable[str] = ()) -> Dict[str, Any]:
    """The asset record as the agent sees it: withheld fields removed."""
    withheld = tuple(withheld)
    unknown = set(withheld) - set(KNOWN_FIELDS)
    if unknown:
        raise ValueError(f"unknown withheld fields: {sorted(unknown)}")
    return {k: v for k, v in facts.items() if k not in withheld}


def fact_sheet(facts: Mapping[str, Any]) -> Dict[str, Any]:
    """The complete record, shown to the human participant."""
    return dict(facts)


def environment_for(
    path: Union[str, Path], asset_id: str, withheld: Iterable[str] = ()
) -> Dict[str, Any]:
    """Load an asset from the environment file and return the agent's masked view."""
    assets = load_assets(path)
    if asset_id not in assets:
        raise KeyError(f"asset {asset_id!r} not in {path}; available: {sorted(assets)}")
    return agent_view(assets[asset_id], withheld)
