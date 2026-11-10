"""Tests for report.py."""

import json

from analyzer import analyze_vulnerabilities
from report import build_json_report, build_markdown_report

SCAN = {
    "status": "success", "file": "app.py", "files_scanned": 1, "total_issues": 1,
    "vulnerabilities": [{
        "id": "F001", "file": "app.py", "test_id": "B307", "type": "blacklist", "severity": "MEDIUM",
        "confidence": "HIGH", "line": 7, "description": "Use of possibly insecure function.",
        "code": "7     eval(x)\n8     print('```')\n", "more_info": "", "cwe": "CWE-78"}],
    "skipped_files": [{"name": "README.md", "reason": "not a Python file"}], "scan_errors": [],
}


def test_markdown_without_analysis():
    md = build_markdown_report(SCAN)
    assert "B307" in md and "app.py" in md and "not confirmed vulnerabilities" in md
    assert "README.md" in md


def test_markdown_with_analysis_and_safe_fences():
    analysis = analyze_vulnerabilities(SCAN, use_ai=False)
    md = build_markdown_report(SCAN, analysis)
    assert "Recommendation:" in md and "Illustrative example" in md
    assert "````python" in md   # fence is longer than the ``` inside the scanned code


def test_json_report_keeps_bandit_and_ai_separate():
    analysis = analyze_vulnerabilities(SCAN, use_ai=False)
    data = json.loads(build_json_report(SCAN, analysis))
    assert data["bandit"]["vulnerabilities"][0]["test_id"] == "B307"
    assert data["interpretation"]["analyses"][0]["test_id"] == "B307"
    assert "disclaimer" in data


def test_json_report_without_analysis():
    assert json.loads(build_json_report(SCAN))["interpretation"] is None

def test_json_report_includes_reachability():
    reachability = [{
        "route": "/search",
        "entry_function": "search",
        "sink": {"name": "eval", "function": "search", "line": 7},
        "source": {"name": "request.args.get", "variable": "user_input"}
    }]

    scan_result = {**SCAN, "reachability": reachability}

    data = json.loads(build_json_report(scan_result))

    assert data["reachability"] == reachability


def test_markdown_report_includes_reachability():
    reachability = [{
        "route": "/search",
        "entry_function": "search",
        "sink": {"name": "eval", "function": "search", "line": 7},
        "source": {"name": "request.args.get", "variable": "user_input"}
    }]

    scan_result = {**SCAN, "reachability": reachability}

    md = build_markdown_report(scan_result)

    assert "Reachability Analysis" in md
    assert "/search" in md
    assert "eval" in md
    assert "request.args.get" in md
    assert "user_input" in md
