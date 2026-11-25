"""
findings.py - the one finding format shared by every scanner.

Findings stay plain dicts (the app, analyzer and report code all use dicts),
but every scanner must build them through make_finding() so the keys match.
"""

from typing import TypedDict

SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


class Finding(TypedDict, total=False):
    id: str
    language: str       # "python" | "javascript"
    tool: str           # "bandit" | "semgrep"
    type: str
    test_id: str        # key into remediation_kb
    severity: str
    confidence: str
    line: int
    file: str
    description: str
    code: str
    more_info: str
    cwe: str
    reachability: str
    evidence: list


def make_finding(*, language, tool, type, test_id, severity, confidence,
                 line, description, code="", more_info="", cwe="", file="") -> Finding:
    return {
        "language": language,
        "tool": tool,
        "type": type,
        "test_id": test_id,
        "severity": severity,
        "confidence": confidence,
        "line": line,
        "description": description,
        "code": code,
        "more_info": more_info,
        "cwe": cwe,
        "file": file,
    }


def sort_and_number(findings: list) -> list:
    """Sort most severe first and assign stable IDs (F001, F002...) in place."""
    findings.sort(key=lambda f: (
        SEVERITY_RANK.get(f["severity"], 3), f["file"], f["line"] or 0
    ))
    for number, finding in enumerate(findings, start=1):
        finding["id"] = f"F{number:03d}"
    return findings