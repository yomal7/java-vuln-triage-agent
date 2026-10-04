"""
run_session.py — run study cases (the experiment itself).

  micro     the agent asks the analyst targeted questions, then resumes
  baseline  the agent stops and hands over a raw transcript

Each case writes one record to results/sessions/ with answers, scores and timing
(analyst active time kept apart from system wait time).

Usage:
  python agent/run_session.py --scenario S01 --condition micro --participant P01
  python agent/run_session.py --scenario S01 --condition baseline --participant P01
  python agent/run_session.py --all --condition micro --simulate     # no human: dev check
"""
import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from protocol.aggregate import load_reachability  # noqa: E402
from protocol.channels import ConsoleChannel, ScriptedChannel  # noqa: E402
from protocol.environment import load_assets  # noqa: E402
from protocol.scenarios import check_scenarios, load_scenarios  # noqa: E402
from protocol.session import CONDITIONS, run_session  # noqa: E402
from protocol.slots import Slot  # noqa: E402

DEFAULT_SCENARIOS = ROOT / "protocol" / "data" / "scenarios.example.json"
DEFAULT_ENVIRONMENT = ROOT / "protocol" / "data" / "environment.example.json"
DEFAULT_REACHABILITY = ROOT / "results" / "reachability.json"
OUT_DIR = ROOT / "results" / "sessions"


def _coord(alert):
    d = alert["dependency"]
    return f"{d['group_id']}:{d['artifact_id']}:{d['version']}"


def simulated_channel(scenario, assets):
    """Dev-only analyst that always gives the correct answer."""
    answers = {}
    for slot in Slot:
        a = scenario.answer_for(slot, assets)
        if a is not None:
            answers[slot.value] = a
    return ScriptedChannel(answers, verdict=scenario.expected and {
        "severity": "Medium",
        "reachable": scenario.expected.get("reachable", "Unclear"),
        "recommended_action": scenario.expected.get("recommended_action", "Needs human review"),
    })


def run_one(scenario, *, alerts_by_coord, assets, reach, condition, participant, simulate,
            max_questions, gate, engine_factory, out_dir=OUT_DIR):
    channel = simulated_channel(scenario, assets) if simulate else ConsoleChannel()
    label = f"{scenario.id}_{condition}_{participant}"
    engine = engine_factory(label)
    record = run_session(
        scenario=scenario,
        alert=alerts_by_coord[scenario.dependency],
        assets=assets,
        reachability_results=reach,
        condition=condition,
        engine=engine,
        channel=channel,
        participant_id=participant,
        max_questions=max_questions,
        gate_environment_on_absent=gate,
    )
    record["simulated"] = simulate
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{label}.json").write_text(json.dumps(record, indent=2, default=str))
    return record


def summarise(r):
    t = r["timing"]
    q = r["escalation"]
    print(
        f"[{r['scenario_id']}/{r['condition']}] decided_by={r['final']['decided_by']} "
        f"questions={len(q['questions'])} unexpected={q['unexpected_questions']} "
        f"score={r['score']} analyst={t['analyst_active_s']}s system_wait={t['system_wait_s']}s"
    )


def main():
    load_dotenv()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", help="scenario id, e.g. S01")
    ap.add_argument("--all", action="store_true", help="run every scenario")
    ap.add_argument("--condition", choices=CONDITIONS, required=True)
    ap.add_argument("--participant", default="SIM")
    ap.add_argument("--simulate", action="store_true", help="scripted correct analyst, no human (development only)")
    ap.add_argument("--max-questions", type=int, default=2)
    ap.add_argument("--gate-env-on-absent", action="store_true")
    ap.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS))
    ap.add_argument("--environment", default=str(DEFAULT_ENVIRONMENT))
    ap.add_argument("--reachability", default=str(DEFAULT_REACHABILITY))
    args = ap.parse_args()
    if not args.scenario and not args.all:
        ap.error("give --scenario ID or --all")

    alerts = json.loads((ROOT / "results" / "alerts.json").read_text())
    alerts_by_coord = {_coord(a): a for a in alerts}
    assets = load_assets(args.environment)
    scenarios = load_scenarios(args.scenarios)
    check_scenarios(scenarios, assets, alerts_by_coord)  # fail early on bad data
    reach = load_reachability(args.reachability)

    chosen = scenarios if args.all else [s for s in scenarios if s.id == args.scenario]
    if not chosen:
        raise SystemExit(f"no scenario {args.scenario!r}; available: {[s.id for s in scenarios]}")

    from triage_agent import LangChainEngine, build_agent  # imported late: needs the API key

    agent, stack = build_agent()
    print(f"[session] llm: {stack.describe()['provider']} models={stack.describe()['models']}")

    def engine_factory(label):
        return LangChainEngine(agent, stack, label, OUT_DIR / "llm" / label)

    for sc in chosen:
        rec = run_one(
            sc, alerts_by_coord=alerts_by_coord, assets=assets, reach=reach,
            condition=args.condition, participant=args.participant, simulate=args.simulate,
            max_questions=args.max_questions, gate=args.gate_env_on_absent,
            engine_factory=engine_factory,
        )
        summarise(rec)
    print(f"\nrecords in {OUT_DIR}/")


if __name__ == "__main__":
    main()
