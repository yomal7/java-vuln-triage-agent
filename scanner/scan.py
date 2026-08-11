"""
scan.py — deterministic alert generator.

This is the "Vulnerability alert" box in the framework diagram: no LLM
involved. It resolves the real dependency tree of target-project/, checks
every dependency against OSV.dev, pulls full advisory detail for any hits,
and cross-references CISA's KEV catalog and FIRST.org's EPSS scores.

Output:
  results/dependency_tree.json  — every resolved dependency (context for the agent)
  results/alerts.json           — only the dependencies with known vulnerabilities

Usage:
  python scanner/scan.py [path/to/maven/project]   # defaults to ../target-project
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import requests

OSV_BASE = "https://api.osv.dev"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BASE = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # OSV allows up to 1000 per batch; kept small for a spike
EPSS_CVE_CHUNK = 150  # FIRST.org caps the 'cve' query param at 2000 chars total

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROJECT = ROOT / "target-project"
RESULTS_DIR = ROOT / "results"


# ---------------------------------------------------------------------------
# 1. Resolve the real dependency tree with Maven
# ---------------------------------------------------------------------------
def run_mvn_dependency_tree(project_dir: Path) -> str:
    print(f"[scan] running `mvn dependency:tree` in {project_dir} ...")
    out_file = project_dir / "_dep_tree_output.txt"
    # -DoutputFile writes clean tree text with no [INFO]/log noise, and is
    # unaffected by log-level flags — more reliable than parsing stdout.
    result = subprocess.run(
        ["mvn", "-q", "dependency:tree", f"-DoutputFile={out_file.name}", "-DoutputType=text"],
        cwd=str(project_dir),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not out_file.exists():
        print(result.stdout)
        print(result.stderr)
        raise RuntimeError(
            "mvn dependency:tree failed — is Maven installed and on PATH? "
            "(brew install maven / apt install maven)"
        )
    text = out_file.read_text()
    out_file.unlink()
    return text


def parse_dependency_tree(raw_output: str) -> list[dict]:
    """Parses Maven's default text-format dependency tree.

    Each indent level adds exactly 3 characters ("|  " or "   ") before the
    branch marker ("+- " or "\\- "), so depth = len(indent_prefix) // 3.
    depth 0 = the project itself (skipped), depth 1 = direct dependency,
    depth 2+ = transitive.
    """
    deps = []
    for raw_line in raw_output.splitlines():
        line = raw_line
        if line.startswith("[INFO]"):
            line = line[len("[INFO]"):]
        if not line.strip():
            continue
        m = re.match(r"^([ |\\+-]*)([\w.\-]+:.+)$", line)
        if not m:
            continue
        prefix, coord = m.group(1), m.group(2).strip()
        depth = len(prefix) // 3
        parts = coord.split(":")
        if len(parts) < 4:
            continue
        group_id, artifact_id, packaging = parts[0], parts[1], parts[2]
        if len(parts) >= 5:
            version, scope = parts[3], parts[4]
        else:
            version, scope = parts[3], "compile"  # the root project line
        if depth == 0:
            continue  # that's the project itself, not a dependency
        deps.append(
            {
                "group_id": group_id,
                "artifact_id": artifact_id,
                "packaging": packaging,
                "version": version,
                "scope": scope,
                "depth": depth,
                "direct": depth == 1,
            }
        )
    return deps


# ---------------------------------------------------------------------------
# 2. Batch-query OSV.dev, then fetch full detail for every hit
# ---------------------------------------------------------------------------
def osv_batch_query(deps: list[dict]) -> dict[tuple, list[str]]:
    """Returns {(group_id, artifact_id, version): [vuln_id, ...]}"""
    unique = {(d["group_id"], d["artifact_id"], d["version"]) for d in deps}
    unique = list(unique)
    hits: dict[tuple, list[str]] = {}

    for i in range(0, len(unique), BATCH_SIZE):
        chunk = unique[i : i + BATCH_SIZE]
        payload = {
            "queries": [
                {
                    "package": {"ecosystem": "Maven", "name": f"{g}:{a}"},
                    "version": v,
                }
                for (g, a, v) in chunk
            ]
        }
        resp = requests.post(f"{OSV_BASE}/v1/querybatch", json=payload, timeout=30)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        for (g, a, v), result in zip(chunk, results):
            vuln_ids = [entry["id"] for entry in result.get("vulns", [])]
            if vuln_ids:
                hits[(g, a, v)] = vuln_ids
    return hits


def osv_get_vuln_detail(vuln_id: str) -> dict:
    resp = requests.get(f"{OSV_BASE}/v1/vulns/{vuln_id}", timeout=30)
    resp.raise_for_status()
    return resp.json()


def extract_cve_aliases(vuln_detail: dict) -> list[str]:
    return [a for a in vuln_detail.get("aliases", []) if a.startswith("CVE-")]


def extract_cwe_ids(vuln_detail: dict) -> list[str]:
    dbspec = vuln_detail.get("database_specific", {}) or {}
    cwes = dbspec.get("cwe_ids") or dbspec.get("cwes") or []
    return cwes


def guess_fixed_version(vuln_detail: dict, group_id: str, artifact_id: str) -> str | None:
    """Best-effort: scan affected[].ranges[].events[] for a 'fixed' version."""
    target_name = f"{group_id}:{artifact_id}"
    fixed_versions = []
    for affected in vuln_detail.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != "Maven" or pkg.get("name") != target_name:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed_versions.append(event["fixed"])
    if not fixed_versions:
        return None
    return sorted(fixed_versions, key=_version_sort_key)[0]


def _version_sort_key(v: str):
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"[.\-]", v))


# ---------------------------------------------------------------------------
# 3. CISA KEV cross-check
# ---------------------------------------------------------------------------
def fetch_kev_cve_set() -> set[str]:
    try:
        resp = requests.get(KEV_FEED_URL, timeout=30)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return {v["cveID"] for v in vulns if "cveID" in v}
    except Exception as e:
        print(f"[scan] warning: couldn't fetch KEV feed ({e}); skipping KEV check")
        return set()


# ---------------------------------------------------------------------------
# 4. EPSS batch lookup — same idea as KEV: fetch once here instead of live
#    per-CVE during the agent loop.
# ---------------------------------------------------------------------------
def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Returns {cve_id: epss_score}. Chunked because FIRST.org caps the
    'cve' query parameter at 2000 characters including commas."""
    unique_cves = sorted(set(cve_ids))
    scores: dict[str, float] = {}
    for i in range(0, len(unique_cves), EPSS_CVE_CHUNK):
        chunk = unique_cves[i : i + EPSS_CVE_CHUNK]
        try:
            resp = requests.get(EPSS_BASE, params={"cve": ",".join(chunk)}, timeout=30)
            resp.raise_for_status()
            for entry in resp.json().get("data", []):
                try:
                    scores[entry["cve"]] = float(entry["epss"])
                except (KeyError, ValueError):
                    continue
        except Exception as e:
            print(f"[scan] warning: EPSS batch lookup failed for one chunk ({e}); "
                  f"affected CVEs will have epss_score: null")
    return scores


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    project_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PROJECT
    RESULTS_DIR.mkdir(exist_ok=True)

    raw_tree = run_mvn_dependency_tree(project_dir)
    deps = parse_dependency_tree(raw_tree)
    print(f"[scan] resolved {len(deps)} dependencies ({sum(d['direct'] for d in deps)} direct)")
    (RESULTS_DIR / "dependency_tree.json").write_text(json.dumps(deps, indent=2))

    print("[scan] querying OSV.dev ...")
    hits = osv_batch_query(deps)
    print(f"[scan] {len(hits)} dependency version(s) have known advisories")

    kev_cves = fetch_kev_cve_set()

    dep_lookup = {(d["group_id"], d["artifact_id"], d["version"]): d for d in deps}
    alerts = []
    all_cves: set[str] = set()
    for (g, a, v), vuln_ids in hits.items():
        dep = dep_lookup[(g, a, v)]
        vulns_detail = []
        for vid in vuln_ids:
            detail = osv_get_vuln_detail(vid)
            cves = extract_cve_aliases(detail)
            all_cves.update(cves)
            vulns_detail.append(
                {
                    "id": vid,
                    "aliases": detail.get("aliases", []),
                    "summary": detail.get("summary", ""),
                    "details": detail.get("details", ""),
                    "cwe_ids": extract_cwe_ids(detail),
                    "severity": detail.get("severity", []),
                    "references": [r.get("url") for r in detail.get("references", [])],
                    "fixed_version_hint": guess_fixed_version(detail, g, a),
                    "in_kev": any(c in kev_cves for c in cves),
                }
            )
        alerts.append(
            {
                "dependency": {
                    "group_id": g,
                    "artifact_id": a,
                    "version": v,
                    "scope": dep["scope"],
                    "direct": dep["direct"],
                    "depth": dep["depth"],
                },
                "vulnerabilities": vulns_detail,
            }
        )

    print(f"[scan] fetching EPSS scores for {len(all_cves)} CVE(s) ...")
    epss_scores = fetch_epss_scores(list(all_cves))
    for alert in alerts:
        for vuln in alert["vulnerabilities"]:
            cves = [a for a in vuln["aliases"] if a.startswith("CVE-")]
            # a vuln can carry multiple CVE aliases; take the highest score found
            matched = [epss_scores[c] for c in cves if c in epss_scores]
            vuln["epss_score"] = max(matched) if matched else None

    (RESULTS_DIR / "alerts.json").write_text(json.dumps(alerts, indent=2))
    print(f"[scan] wrote {len(alerts)} alert(s) to results/alerts.json "
          f"({len(epss_scores)}/{len(all_cves)} CVEs had an EPSS score)")


if __name__ == "__main__":
    main()
