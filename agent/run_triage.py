"""
run_triage.py — runs the agent over every alert in results/alerts.json and
saves each verdict + full tool-call trace to results/triage_runs/.

Runs alerts concurrently (bounded — see TRIAGE_CONCURRENCY below) since each
dependency's investigation is fully independent: separate conversation,
separate results/llm/<dependency>/ log folder, no shared mutable state.
Skips alerts that already have a saved result unless --force is passed.

Usage:
  python agent/run_triage.py            # skip already-triaged alerts
  python agent/run_triage.py --force    # re-run everything
"""
import argparse
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dotenv import load_dotenv

from triage_agent import build_agent, triage_one

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
RUNS_DIR = RESULTS_DIR / "triage_runs"

# Bounded on purpose: past a point, more concurrency just trades sequential
# waiting for 429s and retries against the free-tier RPM cap. 2 is a safe
# default — raise it once you've confirmed your actual rate limit headroom
# with agent/list_models.py / your AI Studio quota page.
TRIAGE_CONCURRENCY = int(os.environ.get("TRIAGE_CONCURRENCY", "2"))


def _out_path(dep: dict) -> Path:
    name = f"{dep['group_id']}_{dep['artifact_id']}_{dep['version']}.json".replace(":", "_")
    return RUNS_DIR / name


def _run_one(agent, alert: dict) -> tuple[str, dict | None, Exception | None, float]:
    dep = alert["dependency"]
    coord = f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}"
    t0 = time.monotonic()
    try:
        run = triage_one(agent, alert)
        return coord, run, None, time.monotonic() - t0
    except Exception as e:
        return coord, None, e, time.monotonic() - t0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="re-triage alerts that already have a saved result")
    args = parser.parse_args()

    alerts_path = RESULTS_DIR / "alerts.json"
    if not alerts_path.exists():
        raise SystemExit("results/alerts.json not found — run scanner/scan.py first.")

    alerts = json.loads(alerts_path.read_text())
    if not alerts:
        print("No vulnerable dependencies found — nothing to triage.")
        return

    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    to_run = []
    for alert in alerts:
        dep = alert["dependency"]
        coord = f"{dep['group_id']}:{dep['artifact_id']}:{dep['version']}"
        if _out_path(dep).exists() and not args.force:
            print(f"[triage] skipping {coord} — already triaged (use --force to redo)")
            continue
        to_run.append(alert)

    if not to_run:
        print("[triage] nothing to do — everything already triaged (use --force to redo).")
        return

    print(f"[triage] {len(to_run)}/{len(alerts)} alert(s) queued, concurrency={TRIAGE_CONCURRENCY}. "
          f"Per-step detail streams below; full request/response logs land in results/llm/<dependency>/.")
    print("[triage] building agent ...")
    agent = build_agent()

    completed = 0
    with ThreadPoolExecutor(max_workers=TRIAGE_CONCURRENCY) as pool:
        futures = {pool.submit(_run_one, agent, alert): alert for alert in to_run}
        for future in as_completed(futures):
            alert = futures[future]
            dep = alert["dependency"]
            coord, run, error, elapsed = future.result()
            completed += 1

            if error is not None:
                print(f"[triage] ({completed}/{len(to_run)}) failed on {coord} after {elapsed:.1f}s: {error}")
                continue

            print(f"[triage] ({completed}/{len(to_run)}) verdict for {coord} ({elapsed:.1f}s): "
                  f"{run['verdict']['severity']} — {run['verdict']['recommended_action']}")
            _out_path(dep).write_text(json.dumps(run, indent=2))

    print(f"\n[triage] done — see {RUNS_DIR}/")


if __name__ == "__main__":
    main()
