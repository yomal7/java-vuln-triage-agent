"""
run_experiments.py — technical experiments for the interim report (no human participants).

Each scenario runs with a simulated analyst who always answers correctly:
  micro  facts withheld; gives TWO conditions from one run:
           gap_no_escalation = the first pass (nothing asked)
           gap_micro         = after the targeted questions and the resume
  full   nothing withheld (upper bound)            -> full_info

Measures E2 (does escalation fire exactly on the designed gaps?) and E3 (how
much do the answers recover?), plus cost (model calls, system time).

Resumable: finished records are skipped, so if a run stops (quota, timeout),
run the same command again and it continues. --summary-only rebuilds the tables.

Usage:
  python agent/run_experiments.py --reps 3
  python agent/run_experiments.py --reps 1 --limit 10          # quick check
  python agent/run_experiments.py --summary-only
"""
import argparse
import json
import statistics
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

import run_session as rs  # noqa: E402
from protocol.aggregate import load_reachability  # noqa: E402
from protocol.environment import load_assets  # noqa: E402
from protocol.scenarios import check_scenarios, load_scenarios  # noqa: E402
from protocol.session import run_session  # noqa: E402
from protocol.slots import ENVIRONMENT_SLOTS  # noqa: E402

ENV_SLOTS = {s.value for s in ENVIRONMENT_SLOTS}
CONDITIONS = ("micro", "full")


def full_info_variant(sc):
    return replace(sc, id=f"{sc.id}-full", withheld=(),
                   expected_slots=tuple(s for s in sc.expected_slots if s not in ENV_SLOTS))


def run_all(scenarios, *, alerts_by_coord, assets, reach, reps, conditions, out_dir, engine_factory,
            max_questions=2, stop_after_failures=5, log=print):
    rec_dir = Path(out_dir) / "records"
    rec_dir.mkdir(parents=True, exist_ok=True)
    stats = {"done": 0, "skipped": 0, "failed": 0, "stopped_early": False}
    in_a_row = 0
    for rep in range(1, reps + 1):              # rep outer: a partial run still covers every scenario once
        for sc in scenarios:
            for cond in conditions:
                path = rec_dir / f"{sc.id}__{cond}__r{rep}.json"
                if path.exists():
                    stats["skipped"] += 1
                    continue
                target = sc if cond == "micro" else full_info_variant(sc)
                try:
                    rec = run_session(
                        scenario=target, alert=alerts_by_coord[sc.dependency], assets=assets,
                        reachability_results=reach, condition="micro",
                        engine=engine_factory(f"{sc.id}_{cond}_r{rep}"),
                        channel=rs.simulated_channel(target, assets),
                        participant_id=f"SIM-r{rep}", max_questions=max_questions,
                    )
                except Exception as exc:  # noqa: BLE001 - keep going, record the failure
                    stats["failed"] += 1
                    in_a_row += 1
                    log(f"[exp] FAILED {sc.id}/{cond}/r{rep}: {type(exc).__name__}: {str(exc)[:200]}")
                    if in_a_row >= stop_after_failures:
                        log(f"[exp] {in_a_row} failures in a row (likely API quota) - stopping; rerun to continue")
                        stats["stopped_early"] = True
                        return stats
                    continue
                in_a_row = 0
                rec.update({"experiment_condition": cond, "rep": rep, "base_scenario": sc.id,
                            "is_control": not sc.expected_slots, "rubric": sc.notes,
                            "expected": dict(sc.expected)})
                path.write_text(json.dumps(rec, indent=2, default=str))
                stats["done"] += 1
                log(f"[exp] {sc.id}/{cond}/r{rep} exact={rec['score'].get('exact')} "
                    f"questions={len(rec['escalation']['questions'])}")
    return stats


# ---------------------------------------------------------------- summary
def _mean_sd(values):
    values = [v for v in values if v is not None]
    if not values:
        return None, None
    return statistics.mean(values), (statistics.stdev(values) if len(values) > 1 else 0.0)


def _rate(flags):
    flags = [f for f in flags if f is not None]
    return sum(1 for f in flags if f) / len(flags) if flags else None


def summarise(out_dir):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    rec_dir = Path(out_dir) / "records"
    recs = [json.loads(p.read_text()) for p in sorted(rec_dir.glob("*.json"))]
    micro = [r for r in recs if r.get("experiment_condition") == "micro"]
    full = [r for r in recs if r.get("experiment_condition") == "full"]
    reps = sorted({r["rep"] for r in recs})

    # E3: accuracy per condition, mean +- sd over repetitions
    def per_rep(records, score_key, field):
        out = []
        for rep in reps:
            vals = [r[score_key].get(field) for r in records if r["rep"] == rep]
            vals = [v for v in vals if v is not None]
            if vals:
                out.append(sum(vals) / len(vals))
        return out

    e3 = {}
    for name, records, key in (("gap_no_escalation", micro, "first_pass_score"),
                               ("gap_micro", micro, "score"),
                               ("full_info", full, "score")):
        e3[name] = {
            "n_records": len(records),
            "exact": _mean_sd(per_rep(records, key, "exact")),
            "action": _mean_sd(per_rep(records, key, "recommended_action_correct")),
            "reachable": _mean_sd(per_rep(records, key, "reachable_correct")),
        }
    # majority-class reference: how often always giving the most common expected action is right
    exp_by_scenario = {r["base_scenario"]: (r.get("expected") or {}).get("recommended_action") for r in micro}
    vals = [v for v in exp_by_scenario.values() if v]
    majority = None
    if vals:
        top, count = Counter(vals).most_common(1)[0]
        majority = {"action": top, "share": count / len(vals)}

    # E2: trigger correctness (micro records)
    escalated = [r for r in micro if r["escalation"]["triggered"]]
    controls = [r for r in micro if r.get("is_control")]
    e2 = {
        "cases": len(micro),
        "designed_gap_missed": sum(len(r["design_check"]["expected_but_resolved"]) for r in micro),
        "undesigned_gap_flagged": sum(len(r["design_check"]["unexpected_unresolved"]) for r in micro),
        "unnecessary_questions": sum(len(r["escalation"]["unexpected_questions"]) for r in micro),
        "control_cases": len(controls),
        "control_cases_with_a_question": sum(1 for r in controls if r["escalation"]["questions"]),
        "questions_per_case": _mean_sd([len(r["escalation"]["questions"]) for r in micro])[0],
        "questions_per_escalated_case": _mean_sd([len(r["escalation"]["questions"]) for r in escalated])[0],
        "skipped_by_cap": sum(len(r["escalation"]["skipped_due_to_cap"]) for r in micro),
    }

    # Cost and behaviour
    def calls(r):
        return (r["first_pass"].get("model_calls") or 0) + (r.get("resume_model_calls") or 0)
    cost = {
        "model_calls_per_case": _mean_sd([calls(r) for r in micro])[0],
        "system_wait_s_per_case": _mean_sd([r["timing"]["system_wait_s"] for r in micro])[0],
        "rate_limit_wait_s_per_case": _mean_sd([r["timing"]["rate_limit_wait_s"] for r in micro])[0],
        "verdict_changed_after_answers": _rate([r.get("resumed_verdict_changed") for r in escalated]),
        "tool_problems": sum(r["first_pass"].get("tool_problems", 0) + (r.get("resume_tool_problems") or 0) for r in micro),
    }
    summary = {"records": len(recs), "repetitions": reps, "e3_accuracy": e3, "majority_class": majority,
               "e2_trigger": e2, "cost": cost}
    (Path(out_dir) / "summary.json").write_text(json.dumps(summary, indent=2))
    md = to_markdown(summary)
    (Path(out_dir) / "summary.md").write_text(md)
    return summary, md


def _fmt(ms, pct=True):
    m, sd = ms
    if m is None:
        return "n/a"
    return f"{m*100:.1f}% ± {sd*100:.1f}" if pct else f"{m:.2f} ± {sd:.2f}"


def to_markdown(s):
    e3, e2, c = s["e3_accuracy"], s["e2_trigger"], s["cost"]
    lines = [f"# Experiment summary ({s['records']} records, repetitions {s['repetitions']})", "",
             "## E3: accuracy by condition (mean ± sd over repetitions)", "",
             "| Condition | Records | Exact (reachable + action) | Action | Reachable |", "|---|---|---|---|---|"]
    for name in ("gap_no_escalation", "gap_micro", "full_info"):
        r = e3[name]
        lines.append(f"| {name} | {r['n_records']} | {_fmt(r['exact'])} | {_fmt(r['action'])} | {_fmt(r['reachable'])} |")
    if s.get("majority_class"):
        mc = s["majority_class"]
        lines += ["", f"Majority-class reference: always answering '{mc['action']}' would be right "
                      f"{mc['share']*100:.1f}% of the time."]
    lines += ["", "## E2: escalation trigger", "", "| Measure | Value |", "|---|---|"]
    for k, v in e2.items():
        lines.append(f"| {k.replace('_', ' ')} | {v if not isinstance(v, float) else f'{v:.2f}'} |")
    lines += ["", "## Cost and behaviour (micro runs)", "", "| Measure | Value |", "|---|---|"]
    for k, v in c.items():
        if isinstance(v, float):
            v = f"{v*100:.1f}%" if k == "verdict_changed_after_answers" else f"{v:.2f}"
        lines.append(f"| {k.replace('_', ' ')} | {v if v is not None else 'n/a'} |")
    return "\n".join(lines) + "\n"


def main():
    load_dotenv()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenarios", default=str(ROOT / "results" / "scenarios.generated.json"))
    ap.add_argument("--environment", default=str(rs.DEFAULT_ENVIRONMENT))
    ap.add_argument("--reachability", default=str(rs.DEFAULT_REACHABILITY))
    ap.add_argument("--out", default=str(ROOT / "results" / "experiments" / "latest"))
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--conditions", nargs="+", choices=CONDITIONS, default=list(CONDITIONS))
    ap.add_argument("--limit", type=int, default=0, help="only the first N scenarios (0 = all)")
    ap.add_argument("--max-questions", type=int, default=2)
    ap.add_argument("--stop-after-failures", type=int, default=5)
    ap.add_argument("--summary-only", action="store_true")
    args = ap.parse_args()

    if not args.summary_only:
        alerts = json.loads((ROOT / "results" / "alerts.json").read_text())
        by_coord = {rs._coord(a): a for a in alerts}
        assets = load_assets(args.environment)
        scenarios = load_scenarios(args.scenarios)
        check_scenarios(scenarios, assets, by_coord)
        if args.limit:
            scenarios = scenarios[: args.limit]
        reach = load_reachability(args.reachability)

        from triage_agent import LangChainEngine, build_agent
        agent, stack = build_agent()
        print(f"[exp] {len(scenarios)} scenarios x {args.reps} reps x {args.conditions}; llm={stack.describe()['models']}")
        out = Path(args.out)

        def engine_factory(label):
            return LangChainEngine(agent, stack, label, out / "llm" / label)

        stats = run_all(scenarios, alerts_by_coord=by_coord, assets=assets, reach=reach, reps=args.reps,
                        conditions=args.conditions, out_dir=out, engine_factory=engine_factory,
                        max_questions=args.max_questions, stop_after_failures=args.stop_after_failures)
        print(f"[exp] {stats}")
    _, md = summarise(args.out)
    print("\n" + md)


if __name__ == "__main__":
    main()