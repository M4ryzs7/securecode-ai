"""Safety net for the hand-written guidance: no entry may recommend dangerous code."""

import pytest

from remediation_kb import CATEGORY_LABELS, KNOWLEDGE_BASE, get_guidance

DANGEROUS_IN_FIXES = ["shell=True", "eval(", "exec(", "pickle.load", "yaml.load(",
                      "verify=False", "os.system", "md5(", "sha1("]


@pytest.mark.parametrize("test_id", sorted(KNOWLEDGE_BASE))
def test_entry_is_well_formed_and_safe(test_id):
    entry = KNOWLEDGE_BASE[test_id]
    assert entry["category"] in CATEGORY_LABELS
    for key in ("explanation", "impact", "recommendation"):
        assert isinstance(entry[key], str) and entry[key].strip()
    for bad in DANGEROUS_IN_FIXES:
        assert bad not in entry["fixed_code"], f"{test_id} example contains {bad}"


def test_unknown_test_id_falls_back_to_bandit_text():
    g = get_guidance("B999", bandit_description="Something odd.")
    assert g["curated"] is False
    assert g["explanation"] == "Something odd."
    assert g["fixed_code"] == ""


def test_b602_guidance_removes_shell_and_uses_list():
    g = get_guidance("B602", severity="HIGH")
    assert "shell=False" in g["fixed_code"]
    assert "check_output" in g["recommendation"]  # explains why swapping functions is not the fix


def test_b307_does_not_oversell_literal_eval():
    g = get_guidance("B307")
    assert "literal_eval" in g["recommendation"]
    assert "ONLY parses" in g["recommendation"]
    assert "literal_eval" not in g["fixed_code"]


def test_b404_is_informational_not_a_vulnerability():
    g = get_guidance("B404")
    assert g["category"] == "informational"
    assert g["fixed_code"] == ""


def test_low_confidence_adds_false_positive_note():
    g = get_guidance("B105", confidence="LOW")
    assert any("false positive" in n for n in g["notes"])


def test_notes_are_not_shared_between_calls():
    get_guidance("B105", confidence="LOW")
    assert get_guidance("B105")["notes"] == KNOWLEDGE_BASE["B105"]["notes"]
