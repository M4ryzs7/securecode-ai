"""
scanner.py - Static analysis layer (Bandit).

Uploaded code is only PARSED by Bandit, never imported or executed.
Public functions:
    scan_file(path, display_name=None)  -> one .py file
    scan_zip(path)                      -> a ZIP containing .py files
    scan_upload(path, original_name)    -> picks the right one by extension
All return a dict with "status": "success" | "error".
"""

import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from safe_zip import ZipSecurityError, extract_python_files
from reachability import analyze_reachability

MAX_FILE_BYTES = 1 * 1024 * 1024
BANDIT_TIMEOUT_SECONDS = 120

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _error(message: str) -> dict:
    return {"status": "error", "error": message}


def _run_bandit(target: Path, recursive: bool = False) -> dict:
    """Run Bandit and return {"ok": True, "report": {...}} or {"ok": False, "error": "..."}."""
    command = [sys.executable, "-m", "bandit", "-f", "json", "-q"]
    if recursive:
        command.append("-r")
    command.append(str(target))

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=BANDIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Scan timed out."}
    except OSError as error:
        return {"ok": False, "error": f"Could not start Bandit: {error}"}

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    if "No module named bandit" in stderr:
        return {"ok": False, "error": "Bandit is not installed. Run: pip install bandit"}

    if not stdout:
        return {"ok": False, "error": stderr or "Bandit returned no output."}

    try:
        return {"ok": True, "report": json.loads(stdout)}
    except json.JSONDecodeError:
        return {"ok": False, "error": "Could not parse Bandit's JSON output."}


def _parse_findings(report: dict, name_for) -> list:
    """Convert Bandit's JSON into our finding dicts. Bandit data stays authoritative."""
    findings = []
    for issue in report.get("results", []):
        cwe = issue.get("issue_cwe") or {}
        findings.append({
            "type": issue.get("test_name", "Unknown"),
            "test_id": issue.get("test_id", ""),
            "severity": str(issue.get("issue_severity", "UNKNOWN")).upper(),
            "confidence": str(issue.get("issue_confidence", "UNKNOWN")).upper(),
            "line": issue.get("line_number"),
            "description": issue.get("issue_text", ""),
            "code": issue.get("code", ""),
            "more_info": issue.get("more_info", ""),
            "cwe": f"CWE-{cwe['id']}" if cwe.get("id") else "",
            "file": name_for(issue.get("filename", "")),
        })

    findings.sort(key=lambda f: (
        _SEVERITY_RANK.get(f["severity"], 3), f["file"], f["line"] or 0
    ))
    for number, finding in enumerate(findings, start=1):
        finding["id"] = f"F{number:03d}"   # stable ID used to link AI output to findings
    return findings


def _parse_errors(report: dict, name_for) -> list:
    return [
        {"file": name_for(e.get("filename", "")), "reason": e.get("reason", "unknown error")}
        for e in report.get("errors", [])
    ]


def _lines_scanned(report: dict) -> int:
    try:
        return int(report["metrics"]["_totals"]["loc"])
    except (KeyError, TypeError, ValueError):
        return 0


def scan_file(file_path: str, display_name: str = None) -> dict:
    """Scan one Python file with Bandit. The source code is analyzed, not executed."""
    path = Path(file_path)

    if not path.is_file():
        return _error("File not found.")

    if path.suffix.lower() != ".py":
        return _error("Only Python files are supported.")

    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return _error(f"File is larger than {MAX_FILE_BYTES // 1024} KB.")

        shown_name = display_name or str(path)
        outcome = _run_bandit(path)
        if not outcome["ok"]:
            return _error(outcome["error"])

        report = outcome["report"]
        name_for = lambda _filename: shown_name
        findings = _parse_findings(report, name_for)
        scan_errors = _parse_errors(report, name_for)

        source_code = path.read_text(encoding="utf-8")
        reachability_results = analyze_reachability(source_code)

        # A file Bandit could not parse must NOT be reported as "clean".
        if scan_errors and not findings:
            return _error(
                "Bandit could not analyze this file (it may contain a syntax error): "
                + scan_errors[0]["reason"]
            )

        warnings = []
        if size == 0:
            warnings.append("The file is empty; there was nothing to scan.")

        return {
            "status": "success",
            "file": shown_name,
            "files_scanned": 1,
            "lines_scanned": _lines_scanned(report),
            "total_issues": len(findings),
            "vulnerabilities": findings,
            "reachability": reachability_results,
            "scan_errors": scan_errors,
            "skipped_files": [],
            "warnings": warnings,
        }
    except Exception as error:  # last-resort guard so the UI never crashes
        return _error(str(error))


def scan_zip(zip_path: str, display_name: str = None) -> dict:
    """Safely extract the .py files of a ZIP and scan them. Nothing is executed."""
    path = Path(zip_path)

    if not path.is_file():
        return _error("File not found.")

    if path.suffix.lower() != ".zip":
        return _error("Only ZIP archives are supported here.")

    try:
        with tempfile.TemporaryDirectory(prefix="securecode_") as tmp:
            root = Path(tmp) / "project"

            try:
                extraction = extract_python_files(path, root)
            except ZipSecurityError as error:
                return _error(f"Archive rejected: {error}")

            if not extraction.extracted:
                return _error("No Python (.py) files were found in the archive.")

            root_resolved = root.resolve()

            def name_for(filename: str) -> str:
                try:
                    return Path(filename).resolve().relative_to(root_resolved).as_posix()
                except (ValueError, OSError):
                    return Path(filename).name

            outcome = _run_bandit(root, recursive=True)
            if not outcome["ok"]:
                return _error(outcome["error"])

            report = outcome["report"]
            findings = _parse_findings(report, name_for)
            scan_errors = _parse_errors(report, name_for)
            reachability_results = []
            warnings = []

            for relative_path in extraction.extracted:
                python_file = root / relative_path

                try:
                    source_code = python_file.read_text(encoding="utf-8")
                    file_results = analyze_reachability(source_code)

                    for entry in file_results:
                        entry["file"] = relative_path

                    reachability_results.extend(file_results)

                except (OSError, UnicodeDecodeError):
                    warnings.append(
                        f"Reachability analysis could not read: {relative_path}"
                    )

            warnings = []
            if scan_errors:
                warnings.append(
                    f"{len(scan_errors)} file(s) could not be analyzed by Bandit "
                    "and are NOT covered by these results."
                )

            return {
                "status": "success",
                "file": display_name or path.name,
                "files_scanned": len(extraction.extracted),
                "lines_scanned": _lines_scanned(report),
                "total_issues": len(findings),
                "vulnerabilities": findings,
                "reachability": reachability_results,
                "scan_errors": scan_errors,
                "skipped_files": extraction.skipped,
                "warnings": warnings,
            }
    except Exception as error:
        return _error(str(error))

def validate_fix_code(fixed_code: str, original_test_id: str) -> dict:
    """
    Validate a proposed Python fix snippet using syntax parsing and Bandit.

    The snippet is analyzed in isolation and is never executed.
    """
    if not isinstance(fixed_code, str) or not fixed_code.strip():
        return {
            "valid": False,
            "reason": "No fix code was provided.",
            "findings": []
        }

    if not isinstance(original_test_id, str) or not original_test_id:
        return {
            "valid": False,
            "reason": "Original Bandit test ID is missing.",
            "findings": []
        }

    try:
        ast.parse(fixed_code)
    except SyntaxError as error:
        return {
            "valid": False,
            "reason": f"Invalid Python syntax: {error}",
            "findings": []
        }

    with tempfile.TemporaryDirectory(prefix="securecode_fix_") as tmp:
        candidate = Path(tmp) / "proposed_fix.py"
        candidate.write_text(fixed_code, encoding="utf-8")

        result = scan_file(str(candidate))

    if result["status"] != "success":
        return {
            "valid": False,
            "reason": result.get("error", "Bandit validation failed."),
            "findings": []
        }

    findings = result["vulnerabilities"]

    if any(f["test_id"] == original_test_id for f in findings):
        return {
            "valid": False,
            "reason": "The original Bandit finding is still present.",
            "findings": findings
        }

    dangerous = [
        f for f in findings
        if f["severity"] in ("HIGH", "MEDIUM")
    ]

    if dangerous:
        return {
            "valid": False,
            "reason": "The proposed fix introduces HIGH or MEDIUM findings.",
            "findings": findings
        }

    return {
        "valid": True,
        "reason": "The snippet passed syntax and Bandit checks.",
        "findings": findings
    }

def scan_upload(file_path: str, original_name: str) -> dict:
    """Scan an uploaded .py or .zip file, reporting the user's original file name."""
    suffix = Path(original_name).suffix.lower()
    if suffix == ".py":
        return scan_file(file_path, display_name=original_name)
    if suffix == ".zip":
        return scan_zip(file_path, display_name=original_name)
    return _error("Unsupported file type. Upload a .py file or a .zip of Python files.")

def validate_fix_code(fixed_code: str, original_test_id: str) -> dict:
    """
    Validate a proposed Python fix snippet using syntax parsing and Bandit.
    The code is never executed.
    """
    if not isinstance(fixed_code, str) or not fixed_code.strip():
        return {
            "valid": False,
            "reason": "No fix code was provided.",
            "findings": []
        }

    if not isinstance(original_test_id, str) or not original_test_id:
        return {
            "valid": False,
            "reason": "Original Bandit test ID is missing.",
            "findings": []
        }

    try:
        ast.parse(fixed_code)
    except SyntaxError as error:
        return {
            "valid": False,
            "reason": f"Invalid Python syntax: {error}",
            "findings": []
        }

    with tempfile.TemporaryDirectory(prefix="securecode_fix_") as tmp:
        candidate = Path(tmp) / "proposed_fix.py"
        candidate.write_text(fixed_code, encoding="utf-8")

        result = scan_file(str(candidate))

    if result["status"] != "success":
        return {
            "valid": False,
            "reason": result.get("error", "Bandit validation failed."),
            "findings": []
        }

    findings = result["vulnerabilities"]

    if any(f["test_id"] == original_test_id for f in findings):
        return {
            "valid": False,
            "reason": "The original Bandit finding is still present.",
            "findings": findings
        }

    dangerous = [
        f for f in findings
        if f["severity"] in ("HIGH", "MEDIUM")
    ]

    if dangerous:
        return {
            "valid": False,
            "reason": "The proposed fix introduces HIGH or MEDIUM findings.",
            "findings": findings
        }

    return {
        "valid": True,
        "reason": "The snippet passed syntax and Bandit checks.",
        "findings": findings
    }