import pytest

from protocol.rubric import POLICY_TEXT, expected_verdict

BASE = dict(scope="compile", reachable="yes", in_kev=False, max_epss=0.01,
            exposure="internal", criticality="low", fix_available=True)


def v(**over):
    return expected_verdict(**{**BASE, **over})


def test_rule1_not_shipped_wins_over_everything():
    assert v(scope="test", in_kev=True, exposure="internet_facing")["recommended_action"] == "Accept risk"
    assert v(scope="provided")["rule"] == 1


def test_rule2_not_reachable():
    assert v(reachable="no")["recommended_action"] == "Upgrade in next cycle"
    assert v(reachable="no", fix_available=False)["recommended_action"] == "Accept risk"
    assert v(reachable="no")["reachable"] == "No"


def test_rule3_kev_and_internet_facing():
    out = v(in_kev=True, exposure="internet_facing")
    assert (out["recommended_action"], out["rule"]) == ("Upgrade immediately", 3)
    assert v(in_kev=True, exposure="internet_facing", fix_available=False)["recommended_action"] == "Mitigate"


def test_rule4_exploit_signal_and_critical_asset():
    assert v(in_kev=True, criticality="critical")["rule"] == 4
    assert v(max_epss=0.5, criticality="high")["recommended_action"] == "Upgrade immediately"
    assert v(max_epss=0.05, criticality="high")["rule"] == 5          # below threshold


def test_rule5_everything_else_reachable():
    assert v()["recommended_action"] == "Upgrade in next cycle"
    assert v(fix_available=False)["recommended_action"] == "Mitigate"


def test_rule6_unclear_reachability():
    out = v(reachable="unclear")
    assert (out["recommended_action"], out["reachable"], out["rule"]) == ("Needs human review", "Unclear", 6)


def test_examples_used_so_far_are_reproduced():
    # S01 log4j / internet-facing + KEV ; S02 spring absent ; S03 junit test scope ; S04 databind absent
    assert v(in_kev=True, exposure="internet_facing", criticality="high")["recommended_action"] == "Upgrade immediately"
    assert v(reachable="no")["recommended_action"] == "Upgrade in next cycle"
    assert v(scope="test", reachable="no")["recommended_action"] == "Accept risk"


def test_policy_text_lists_all_six_rules():
    for n in range(1, 7):
        assert f"{n}." in POLICY_TEXT