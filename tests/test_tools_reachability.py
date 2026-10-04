"""The agent's reachability evidence must be the same stored result the slot check reads."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ALERTS = ROOT / "results" / "alerts.json"
STUB = ROOT / "results" / "reachability.json"
pytestmark = pytest.mark.skipif(not (ALERTS.exists() and STUB.exists()), reason="needs results/ data")


def coords(artifact):
    a = next(x for x in json.loads(ALERTS.read_text()) if x["dependency"]["artifact_id"] == artifact)
    d = a["dependency"]
    return {"group_id": d["group_id"], "artifact_id": d["artifact_id"], "version": d["version"]}


def reach(artifact):
    import tools
    return json.loads(tools.check_reachability.invoke(coords(artifact)))


def test_stored_tool_returns_the_same_status_the_slot_check_uses():
    assert reach("log4j-core")["status"] == "ambiguous"
    for artifact in ("jackson-databind", "jackson-core", "spring-core", "commons-collections", "junit"):
        assert reach(artifact)["status"] == "absent", artifact


def test_the_comment_match_is_no_longer_evidence():
    """jackson-databind is only *mentioned in a comment*; the grep tool reports a hit,
    the stored analysis (what the agent now sees) reports absent."""
    import tools
    grep = tools.search_code_usage.invoke({"artifact_id": "jackson-databind"})
    assert "App.java" in grep                              # v1 false positive still reproducible
    assert reach("jackson-databind")["status"] == "absent"


def test_ambiguous_result_carries_its_reason_and_cause():
    out = reach("log4j-core")
    assert out["details"][0]["ambiguity_cause"] == "no_method_data"
    assert out["details"][0]["reason"]


def test_missing_entry_is_reported_as_error_not_absent(tmp_path, monkeypatch):
    import tools
    empty = tmp_path / "reachability.json"
    empty.write_text(json.dumps({"results": []}))
    monkeypatch.setattr(tools, "REACHABILITY_PATH", empty)
    assert reach("junit")["status"] == "error"


def test_unknown_dependency():
    import tools
    out = tools.check_reachability.invoke({"group_id": "x", "artifact_id": "y", "version": "1"})
    assert out.startswith("unknown")


def test_default_tool_set_uses_the_stored_file(monkeypatch):
    import tools
    monkeypatch.delenv("REACHABILITY_SOURCE", raising=False)
    names = [t.name for t in tools.get_tools()]
    assert "check_reachability" in names and "search_code_usage" not in names


def test_grep_switch_restores_the_v1_baseline_tool(monkeypatch):
    import tools
    monkeypatch.setenv("REACHABILITY_SOURCE", "grep")
    names = [t.name for t in tools.get_tools()]
    assert "search_code_usage" in names and "check_reachability" not in names


def test_bad_switch_value_fails_loudly(monkeypatch):
    import tools
    monkeypatch.setenv("REACHABILITY_SOURCE", "magic")
    with pytest.raises(ValueError):
        tools.get_tools()


def test_system_prompt_matches_the_tool_in_use():
    import triage_agent
    assert "check_reachability" in triage_agent.build_system_prompt("stored")
    assert "check_reachability" not in triage_agent.build_system_prompt("grep")
    assert "search for the artifact id" in triage_agent.build_system_prompt("grep")


def test_a_garbled_group_id_still_finds_the_dependency():
    """Seen live: the model sent group_id="org.springframework:`,version:" for spring-core."""
    import tools
    out = tools.check_fix_version.invoke(
        {"group_id": "org.springframework:`,version:", "artifact_id": "spring-core", "version": "5.2.0.RELEASE"})
    assert not out.startswith("unknown")
    assert "5.2.19" in out


def test_a_wrong_dependency_is_refused_and_the_reply_lists_the_valid_ones():
    import tools
    out = tools.check_kev_status.invoke({"group_id": "x", "artifact_id": "nope", "version": "9"})
    assert out.startswith("unknown")
    assert "org.springframework:spring-core:5.2.0.RELEASE" in out     # lets the model self-correct


def test_ambiguous_partial_match_is_not_guessed(monkeypatch):
    import tools
    d = {"group_id": "a", "artifact_id": "same", "version": "1"}
    twin = {"group_id": "b", "artifact_id": "same", "version": "1"}
    monkeypatch.setattr(tools, "_ALERTS", [{"dependency": d, "vulnerabilities": []},
                                           {"dependency": twin, "vulnerabilities": []}])
    assert tools._find_alert("zzz", "same", "1") is None
    assert tools._find_alert("a", "same", "1") is not None


def test_reachability_reports_the_real_coordinates_even_if_the_call_was_garbled():
    import tools
    out = json.loads(tools.check_reachability.invoke(
        {"group_id": "garbage", "artifact_id": "spring-core", "version": "5.2.0.RELEASE"}))
    assert out["dependency"] == "org.springframework:spring-core:5.2.0.RELEASE"
    assert out["status"] == "absent"