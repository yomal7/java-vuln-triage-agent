"""Shared command-line options for the slot check (shadow mode)."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Callable, Dict

from .aggregate import load_reachability
from .environment import KNOWN_FIELDS, environment_for
from .report import dependency_slot_report

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENVIRONMENT = ROOT / "protocol" / "data" / "environment.example.json"
DEFAULT_REACHABILITY = ROOT / "results" / "reachability.json"


def add_slot_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("slot check (shadow mode: recorded, does not change the agent)")
    g.add_argument("--asset", default="mock-app-01", help="asset id in the environment file")
    g.add_argument(
        "--withhold", nargs="*", default=[], choices=list(KNOWN_FIELDS),
        help="environment fields the agent is NOT given (creates a gap)",
    )
    g.add_argument("--environment", default=str(DEFAULT_ENVIRONMENT))
    g.add_argument("--reachability", default=str(DEFAULT_REACHABILITY))
    g.add_argument(
        "--gate-env-on-absent", action="store_true",
        help="do not require environment slots when reachability is confirmed absent",
    )


def make_slot_reporter(args: argparse.Namespace) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Load inputs once; return a function alert -> slot report."""
    results = load_reachability(args.reachability)
    environment = environment_for(args.environment, args.asset, args.withhold)
    return lambda alert: dependency_slot_report(
        alert, results, environment, gate_environment_on_absent=args.gate_env_on_absent
    )
