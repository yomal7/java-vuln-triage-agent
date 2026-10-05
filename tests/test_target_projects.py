"""Target projects: the research data is consistent, and the E1 / generator code works."""
import importlib
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TP = ROOT / "target-projects"
PROJECTS = ["orders-service", "report-batch"]


def pom_artifacts(project):
    text = (TP / project / "pom.xml").read_text()
    deps = re.findall(r"<dependency>(.*?)</dependency>", text, re.S)
    return {re.search(r"<artifactId>(.*?)</artifactId>", d).group(1) for d in deps}


# ---------------------------------------------------------------- data consistency
def test_every_pom_is_well_formed_xml():
    """Caught too late once: '--' inside an XML comment makes Maven refuse the pom."""
    import xml.etree.ElementTree as ET
    poms = list(TP.rglob("pom.xml")) + [ROOT / "reachability-engine" / "pom.xml"]
    assert len(poms) == 3
    for pom in poms:
        ET.parse(pom)
        for comment in re.findall(r"<!--(.*?)-->", pom.read_text(), re.S):
            assert "--" not in comment, pom


def test_designed_vulnerable_versions_are_not_already_fixed():
    """commons-io 2.7 is the FIXED version of CVE-2021-29425; the designed case needs 2.6."""
    text = (TP / "report-batch" / "pom.xml").read_text()
    assert re.search(r"<artifactId>commons-io</artifactId>\s*<version>2\.6</version>", text)



@pytest.mark.parametrize("project", PROJECTS)
def test_every_dependency_has_ground_truth_and_vice_versa(project):
    gt = json.loads((TP / project / "ground_truth.json").read_text())
    gt_artifacts = {e["artifact_id"] for e in gt["entries"]}
    assert gt_artifacts == pom_artifacts(project)
    for e in gt["entries"]:
        assert e["reachable"] in ("yes", "no") and e["evidence"]


@pytest.mark.parametrize("project", PROJECTS)
def test_ground_truth_asset_exists(project):
    gt = json.loads((TP / project / "ground_truth.json").read_text())
    assets = json.loads((TP / "environment.json").read_text())["assets"]
    assert gt["asset_id"] in assets


def test_vulnerable_methods_are_well_formed_and_belong_to_a_project():
    data = json.loads((TP / "vulnerable_methods.json").read_text())
    all_artifacts = set().union(*(pom_artifacts(p) for p in PROJECTS))
    for e in data["entries"]:
        assert e["artifact_id"] in all_artifacts
        for m in e["methods"]:
            cls, name = m.split("#")
            assert "." in cls and name


def test_environment_assets_have_every_fact():
    from protocol.environment import KNOWN_FIELDS
    for facts in json.loads((TP / "environment.json").read_text())["assets"].values():
        assert all(f in facts for f in KNOWN_FIELDS)


def test_designed_cases_are_present_in_the_code():
    """The cases the ground truth describes really are in the source."""
    orders = "\n".join(f.read_text() for f in (TP / "orders-service" / "src").rglob("*.java"))
    batch = "\n".join(f.read_text() for f in (TP / "report-batch" / "src").rglob("*.java"))
    assert "StringSubstitutor.createInterpolator()" in orders
    assert "new Yaml().load(" in orders
    assert "matcher.match(" in orders
    assert "ImmutableList.of(" in orders and "createTempDir" not in orders
    assert "h2" in orders and "org.h2" not in orders                     # comment only: text-search trap
    assert "FilenameUtils.normalize(" in batch
    assert "Class.forName(" in batch and ".fromXML(" in batch           # reachable only via reflection
    assert "commons-collections" in batch and "org.apache.commons.collections" not in batch


# ---------------------------------------------------------------- E1 evaluation
def _alert(artifact, vulns):
    return {"dependency": {"group_id": "g", "artifact_id": artifact, "version": "1", "scope": "compile"},
            "vulnerabilities": [{"id": v, "aliases": a} for v, a in vulns]}


def test_eval_scores_v1_and_engine_against_truth():
    import eval_reachability as ev
    alerts = [_alert("lib-a", [("GHSA-1", ["CVE-1"]), ("GHSA-2", [])]), _alert("lib-b", [("GHSA-3", [])])]
    truth = {"entries": [{"artifact_id": "lib-a", "vulnerability": "CVE-1", "reachable": "yes"},
                         {"artifact_id": "lib-a", "vulnerability": "*", "reachable": "no"},
                         {"artifact_id": "lib-b", "vulnerability": "*", "reachable": "no"}]}
    methods = {"entries": [{"artifact_id": "lib-a", "vulnerability": "CVE-1", "methods": ["x.Danger#run"]}]}
    engine = {"results": [
        {"dependency": {"artifact_id": "lib-a"}, "vulnerability_id": "GHSA-1", "status": "confirmed", "reason": "r"},
        {"dependency": {"artifact_id": "lib-a"}, "vulnerability_id": "GHSA-2", "status": "ambiguous", "reason": "r"},
        {"dependency": {"artifact_id": "lib-b"}, "vulnerability_id": "GHSA-3", "status": "absent", "reason": "r"}]}
    src = "// lib-b is mentioned only in this comment\nnew Danger().run();"
    rows = ev.evaluate_project("p", alerts, engine, truth, methods, src)
    by = {r["vulnerability"]: r for r in rows}
    assert by["GHSA-1"]["truth"] == "yes" and by["GHSA-2"]["truth"] == "no"   # alias match, then '*'
    assert by["GHSA-3"]["v1"] == "yes"                                       # text search fooled by the comment
    m_v1, m_eng = ev.metrics(rows, "v1"), ev.metrics(rows, "engine")
    assert m_v1["fp"] >= 1
    assert (m_eng["tp"], m_eng["tn"], m_eng["fp"], m_eng["undecided"]) == (1, 1, 0, 1)
    md = ev.to_markdown(rows, m_v1, m_eng)
    assert "v1 text search" in md and "SootUp engine" in md and "Dependency level" in md
    deps = {d["artifact"]: d for d in ev.dependency_rows(rows)}
    assert deps["lib-a"]["truth"] == "yes" and deps["lib-a"]["engine"] == "yes"   # any yes wins
    assert deps["lib-b"]["v1"] == "yes" and deps["lib-b"]["truth"] == "no"


def test_eval_marks_missing_engine_results():
    import eval_reachability as ev
    rows = ev.evaluate_project("p", [_alert("lib-a", [("GHSA-1", [])])], {"results": []},
                               {"entries": [{"artifact_id": "lib-a", "vulnerability": "*", "reachable": "no"}]},
                               {"entries": []}, "")
    assert rows[0]["engine"] == "missing"


# ---------------------------------------------------------------- generator with ground truth
def test_generator_uses_documented_ground_truth_and_prefix():
    import generate_scenarios as gs
    alerts = [_alert("lib-a", [("GHSA-1", ["CVE-1"])])]
    alerts[0]["vulnerabilities"][0].update({"in_kev": True, "epss_score": 0.5, "fixed_version_hint": "2"})
    assets = {"web": {"network_exposure": "internet_facing", "asset_criticality": "high", "patch_window": "weekly"}}
    reach = [{"dependency": alerts[0]["dependency"], "vulnerability_id": "*", "status": "ambiguous"}]
    truth = {"entries": [{"artifact_id": "lib-a", "vulnerability": "CVE-1", "reachable": "yes"}]}
    scs = gs.build(alerts, assets, reach, ground_truth=truth, prefix="O")
    assert scs[0].id == "O001"
    assert scs[0].expected["reachable"] == "Yes"
    assert scs[0].expected["recommended_action"] == "Upgrade immediately"
    assert scs[0].analyst_answers == {"reachability": "yes"}             # engine ambiguous -> analyst knows the truth
    assert "reachability" in scs[0].expected_slots


def test_truth_from_file_any_yes_wins():
    import generate_scenarios as gs
    alert = _alert("lib-a", [("GHSA-1", []), ("GHSA-2", ["CVE-2"])])
    truth = {"entries": [{"artifact_id": "lib-a", "vulnerability": "CVE-2", "reachable": "yes"},
                         {"artifact_id": "lib-a", "vulnerability": "*", "reachable": "no"}]}
    assert gs.truth_from_file(truth, alert) == "yes"
    assert gs.truth_from_file({"entries": []}, alert) is None


# ---------------------------------------------------------------- per-project tool files
def test_tools_read_per_project_files_from_the_environment(tmp_path, monkeypatch):
    import tools
    alerts = [_alert("lib-z", [("GHSA-9", [])])]
    alerts[0]["vulnerabilities"][0]["in_kev"] = True
    (tmp_path / "alerts.json").write_text(json.dumps(alerts))
    (tmp_path / "dependency_tree.json").write_text("[]")
    monkeypatch.setenv("ALERTS_FILE", str(tmp_path / "alerts.json"))
    try:
        importlib.reload(tools)
        out = tools.check_kev_status.invoke({"group_id": "g", "artifact_id": "lib-z", "version": "1"})
        assert json.loads(out) == {"GHSA-9": True}
    finally:
        monkeypatch.delenv("ALERTS_FILE")
        importlib.reload(tools)