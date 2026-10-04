"""
slot_report.py — shadow-mode slot check over results/alerts.json.

No LLM and no API calls: it only reads the scanner output, reachability.json and
the mock environment, and answers "for each dependency, which required slots are
resolved and which are still missing?". Writes results/slot_reports/*.json.

Usage:
  python agent/slot_report.py
  python agent/slot_report.py --withhold asset_criticality
  python agent/slot_report.py --withhold network_exposure asset_criticality --gate-env-on-absent
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from protocol.cli import add_slot_args, make_slot_reporter  # noqa: E402

OUT_DIR = ROOT / "results" / "slot_reports"
COLUMNS = [
    ("reachability", "reach"),
    ("exploitation_status", "exploit"),
    ("fix_availability", "fix"),
    ("network_exposure", "exposure"),
    ("asset_criticality", "critical"),
    ("patch_window", "patch"),
]
MARK = {"resolved": "ok", "unresolved": "MISSING", "not_required": "-"}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_slot_args(parser)
    args = parser.parse_args()

    alerts = json.loads((ROOT / "results" / "alerts.json").read_text())
    reporter = make_slot_reporter(args)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"asset={args.asset} withheld={args.withhold or 'none'} gate={args.gate_env_on_absent}\n")
    header = f"{'dependency':58}" + "".join(f"{label:>9}" for _, label in COLUMNS) + "  escalate?"
    print(header)
    print("-" * len(header))
    for alert in alerts:
        report = reporter(alert)
        dep = report["dependency"]
        (OUT_DIR / (dep.replace(":", "_") + ".json")).write_text(json.dumps(report, indent=2))
        cells = "".join(f"{MARK[report['slots'][key]['state']]:>9}" for key, _ in COLUMNS)
        print(f"{dep:58}{cells}  {'YES' if report['needs_escalation'] else 'no'}")
    print(f"\nwrote {OUT_DIR}/")


if __name__ == "__main__":
    main()
