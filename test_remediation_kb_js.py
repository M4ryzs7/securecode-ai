import re
from pathlib import Path

from remediation_kb import KNOWLEDGE_BASE, get_guidance

JS_RULE_IDS = ["js-eval", "js-new-function", "js-innerhtml", "js-document-write"]


def test_every_js_rule_has_curated_guidance():
    for rule_id in JS_RULE_IDS:
        guidance = get_guidance(rule_id)
        assert guidance["curated"] is True
        assert guidance["recommendation"]
        assert guidance["fixed_code"].strip()


def test_every_rule_in_rules_file_has_a_kb_entry():
    rules_file = Path(__file__).parent / "rules" / "js_security.yml"
    ids = re.findall(r"^\s*-\s*id:\s*(\S+)", rules_file.read_text(encoding="utf-8"),
                     flags=re.MULTILINE)
    assert ids
    missing = [rule_id for rule_id in ids if rule_id not in KNOWLEDGE_BASE]
    assert not missing, f"Rules without KB entry: {missing}"
