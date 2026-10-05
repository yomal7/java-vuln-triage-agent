"""
eval_reachability.py — Experiment E1: is the reachability slot reliable?

For every advisory of every target project, compares two analyses with the
documented ground truth (target-projects/<project>/ground_truth.json):

  v1 text search  the original approach: reachable if the artifact id or a
                  vulnerable class name appears anywhere in the source text
  SootUp engine   CHA call graph + curated vulnerable methods (reachability.json)

Usage:
  python agent/eval_reachability.py --projects orders-service report-batch
Writes results/reachability_eval.md and .json.
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TP_DIR = ROOT / "target-projects"


def entry_for(entries, artifact, vuln):
    """Match an advisory to a ground-truth / methods entry: id or alias first, then '*'."""
    ids = {vuln["id"], *vuln.get("aliases", [])}
    mine = [e for e in entries if e["artifact_id"] == artifact]
    return next((e for e in mine if e["vulnerability"] in ids), None) or \
        next((e for e in mine if e["vulnerability"] == "*"), None)


def v1_text_search(src_text, artifact, targets):
    """Reachable if the artifact id or any vulnerable class's simple name appears in the source."""
    needles = [artifact] + [t.split("#")[0].rsplit(".", 1)[-1] for t in targets]
    return "yes" if any(re.search(re.escape(n), src_text, re.IGNORECASE) for n in needles) else "no"


ENGINE_LABEL = {"confirmed": "yes", "absent": "no", "ambiguous": "ambiguous", "error": "error"}


def evaluate_project(project, alerts, engine, truth, methods, src_text):
    engine_by_key = {(r["dependency"]["artifact_id"], r["vulnerability_id"]): r for r in engine.get("results", [])}
    rows = []
    for alert in alerts:
        artifact = alert["dependency"]["artifact_id"]
        for vuln in alert["vulnerabilities"]:
            gt = entry_for(truth["entries"], artifact, vuln)
            if gt is None:
                continue  # advisory outside the designed ground truth
            m = entry_for(methods["entries"], artifact, vuln)
            targets = m["methods"] if m else []
            er = engine_by_key.get((artifact, vuln["id"]))
            rows.append({
                "project": project,
                "artifact": artifact,
                "vulnerability": vuln["id"],
                "cve": next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), ""),
                "truth": gt["reachable"],
                "v1": v1_text_search(src_text, artifact, targets),
                "engine": ENGINE_LABEL.get(er["status"], "error") if er else "missing",
                "engine_reason": er.get("reason", "") if er else "no engine result",
                "ambiguity_cause": er.get("ambiguity_cause") if er else None,
            })
    return rows


def metrics(rows, tool):
    tp = sum(1 for r in rows if r[tool] == "yes" and r["truth"] == "yes")
    fp = sum(1 for r in rows if r[tool] == "yes" and r["truth"] == "no")
    tn = sum(1 for r in rows if r[tool] == "no" and r["truth"] == "no")
    fn = sum(1 for r in rows if r[tool] == "no" and r["truth"] == "yes")
    undecided = sum(1 for r in rows if r[tool] not in ("yes", "no"))
    decided = tp + fp + tn + fn
    positives = sum(1 for r in rows if r["truth"] == "yes")
    return {
        "advisories": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "undecided": undecided,
        "decided_share": decided / len(rows) if rows else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,                       # among cases it decided
        "recall_all": tp / positives if positives else None,                  # among ALL truly reachable
        "accuracy_decided": (tp + tn) / decided if decided else None,
        "accuracy_all": (tp + tn) / len(rows) if rows else None,              # undecided counted as wrong
        "always_reachable_accuracy": positives / len(rows) if rows else None, # reference baseline
    }


def dependency_rows(rows):
    """One row per (project, dependency): reachable if any of its advisories is.
    Stops one library with many advisories (xstream: 18) from dominating the scores."""
    groups = {}
    for r in rows:
        groups.setdefault((r["project"], r["artifact"]), []).append(r)
    out = []
    for (project, artifact), rs in sorted(groups.items()):
        def collapse(tool):
            vals = [x[tool] for x in rs]
            if "yes" in vals:
                return "yes"
            if all(v == "no" for v in vals):
                return "no"
            return "ambiguous"
        out.append({"project": project, "artifact": artifact, "advisories": len(rs),
                    "truth": "yes" if any(x["truth"] == "yes" for x in rs) else "no",
                    "v1": collapse("v1"), "engine": collapse("engine")})
    return out


def pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


def _tables(title_rows, rows_by_tool):
    lines = ["| Analysis | TP | FP | TN | FN | Undecided |", "|---|---|---|---|---|---|"]
    for name, m in rows_by_tool:
        lines.append(f"| {name} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | {m['undecided']} |")
    lines += ["", "| Analysis | Answered | Precision (answered) | Found of all reachable | Accuracy (answered) | Accuracy (unanswered = wrong) |",
              "|---|---|---|---|---|---|"]
    for name, m in rows_by_tool:
        lines.append(f"| {name} | {pct(m['decided_share'])} | {pct(m['precision'])} | {pct(m['recall_all'])} | "
                     f"{pct(m['accuracy_decided'])} | {pct(m['accuracy_all'])} |")
    ref = rows_by_tool[0][1]["always_reachable_accuracy"]
    lines += ["", f"Reference: answering \"reachable\" for everything would be right {pct(ref)} of the time."]
    return lines


def to_markdown(rows, m_v1, m_eng):
    deps = dependency_rows(rows)
    lines = ["# E1: reachability accuracy against ground truth", "",
             f"{len(rows)} advisories ({sum(1 for r in rows if r['truth'] == 'yes')} truly reachable) across "
             f"{len({r['project'] for r in rows})} target projects.", "",
             "How to read: the engine may answer *ambiguous* (undecided) instead of guessing; those cases are the "
             "ones the escalation protocol hands to the analyst. 'Accuracy (answered)' only counts cases a "
             "tool answered, so read it together with 'Answered'. The ground truth and the curated vulnerable "
             "methods were written by the researcher for these projects, so this validates the pipeline on "
             "designed cases, not SootUp in general.", "",
             "## Advisory level", ""]
    lines += _tables("advisory", [("v1 text search", m_v1), ("SootUp engine", m_eng)])
    lines += ["", f"## Dependency level ({len(deps)} dependencies; each counted once)", ""]
    lines += _tables("dependency", [("v1 text search", metrics(deps, "v1")), ("SootUp engine", metrics(deps, "engine"))])
    lines += ["", "## Per dependency", "", "| Project | Dependency | Advisories | Truth | v1 | Engine | Engine reason |",
              "|---|---|---|---|---|---|---|"]
    grouped = {}
    for r in rows:
        key = (r["project"], r["artifact"], r["truth"], r["v1"], r["engine"], r["engine_reason"])
        grouped[key] = grouped.get(key, 0) + 1
    for (proj, art, truth, v1, eng, reason), n in sorted(grouped.items()):
        lines.append(f"| {proj} | {art} | {n} | {truth} | {v1} | {eng} | {reason} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--projects", nargs="+", default=["orders-service", "report-batch"])
    ap.add_argument("--results", default=str(ROOT / "results"), help="folder holding <project>/alerts.json etc.")
    ap.add_argument("--methods", default=str(TP_DIR / "vulnerable_methods.json"))
    ap.add_argument("--out", default=str(ROOT / "results" / "reachability_eval"))
    args = ap.parse_args()

    methods = json.loads(Path(args.methods).read_text())
    rows = []
    for p in args.projects:
        res = Path(args.results) / p
        alerts = json.loads((res / "alerts.json").read_text())
        engine_path = res / "reachability.json"
        engine = json.loads(engine_path.read_text()) if engine_path.exists() else {"results": []}
        truth = json.loads((TP_DIR / p / "ground_truth.json").read_text())
        src_text = "\n".join(f.read_text() for f in (TP_DIR / p / "src").rglob("*.java"))
        rows += evaluate_project(p, alerts, engine, truth, methods, src_text)

    m_v1, m_eng = metrics(rows, "v1"), metrics(rows, "engine")
    md = to_markdown(rows, m_v1, m_eng)
    Path(args.out + ".md").write_text(md)
    deps = dependency_rows(rows)
    Path(args.out + ".json").write_text(json.dumps({
        "advisory_level": {"v1": m_v1, "engine": m_eng},
        "dependency_level": {"v1": metrics(deps, "v1"), "engine": metrics(deps, "engine")},
        "rows": rows, "dependency_rows": deps}, indent=2))
    print(md)


if __name__ == "__main__":
    main()