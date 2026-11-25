import shutil
import pytest

from semgrep_scanner import parse_semgrep, scan_js_file

FAKE_REPORT = {
    "results": [{
        "check_id": "javascript.lang.security.audit.eval-detected",
        "path": "x.js",
        "start": {"line": 2}, "end": {"line": 2},
        "extra": {
            "message": "eval detected",
            "severity": "ERROR",
            "lines": "requires login",
            "metadata": {"cwe": ["CWE-95: Eval Injection"], "confidence": "HIGH"},
        },
    }],
    "errors": [],
}


def test_parse_semgrep_maps_to_finding_format():
    findings = parse_semgrep(FAKE_REPORT, lambda _p: "x.js")
    f = findings[0]
    assert f["id"] == "F001"
    assert f["language"] == "javascript" and f["tool"] == "semgrep"
    assert f["severity"] == "HIGH" and f["confidence"] == "HIGH"
    assert f["cwe"] == "CWE-95"
    assert f["line"] == 2 and f["file"] == "x.js"


def test_rejects_non_js_file(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("x = 1\n")
    assert scan_js_file(str(p))["status"] == "error"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_scan_js_file_finds_eval(tmp_path):
    p = tmp_path / "sample.js"
    p.write_text("const q = req.query.q;\neval(q);\n")
    result = scan_js_file(str(p), display_name="sample.js")
    assert result["status"] == "success"
    assert result["total_issues"] >= 1
    assert all(f["language"] == "javascript" for f in result["vulnerabilities"])