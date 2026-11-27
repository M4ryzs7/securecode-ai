"""
semgrep_scanner.py - JavaScript static analysis layer (Semgrep).

Like scanner.py, uploaded code is only PARSED by Semgrep, never executed.
Returns the same result shape as scanner.scan_file().
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from findings import make_finding, sort_and_number

JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs"}
MAX_FILE_BYTES = 1 * 1024 * 1024
SEMGREP_TIMEOUT_SECONDS = 180
RULES_FILE = Path(__file__).parent / "rules" / "js_security.yml"
DEFAULT_CONFIG = str(RULES_FILE)
SNIPPET_CONTEXT_LINES = 2

_SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def _error(message: str) -> dict:
    return {"status": "error", "error": message}


def run_semgrep(target: Path, config: str = DEFAULT_CONFIG) -> dict:
    """Run Semgrep and return {"ok": True, "report": {...}} or {"ok": False, "error": "..."}."""
    exe = shutil.which("semgrep")
    if exe is None:
        return {"ok": False, "error": "Semgrep is not installed. Run: pip install semgrep"}

    configs = config if isinstance(config, (list, tuple)) else [config]

    command = [
        exe, "scan",
        "--json", "--quiet",
        "--metrics=off",
        "--disable-version-check",
    ]

    for cfg in configs:
        command.extend(["--config", cfg])

    command.append(str(target))

    env = {**os.environ, "PYTHONUTF8": "1"}

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=SEMGREP_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Scan timed out."}
    except OSError as error:
        return {"ok": False, "error": f"Could not start Semgrep: {error}"}

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    if not stdout:
        return {"ok": False, "error": stderr or "Semgrep returned no output."}
    try:
        return {"ok": True, "report": json.loads(stdout)}
    except json.JSONDecodeError:
        return {"ok": False, "error": "Could not parse Semgrep's JSON output."}


def _snippet(path: str, start: int, end: int) -> str:
    """Read the code ourselves: Semgrep may return 'requires login' instead of code."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    first = max(0, (start or 1) - 1 - SNIPPET_CONTEXT_LINES)
    last = min(len(lines), (end or start or 1) + SNIPPET_CONTEXT_LINES)
    return "\n".join(lines[first:last])


def _cwe(metadata: dict) -> str:
    raw = metadata.get("cwe")
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    match = re.search(r"CWE-\d+", str(raw or ""))
    return match.group(0) if match else ""


def parse_semgrep(report: dict, name_for, short_ids: bool = False) -> list:
    """Convert Semgrep's JSON into our finding dicts."""
    findings = []
    for result in report.get("results", []):
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        check_id = result.get("check_id", "unknown")
        rule_id = check_id.rsplit(".", 1)[-1] if short_ids else check_id
        start = (result.get("start") or {}).get("line")
        end = (result.get("end") or {}).get("line")
        references = metadata.get("references")

        findings.append(make_finding(
            language="javascript",
            tool="semgrep",
            type=metadata.get("title") or check_id.rsplit(".", 1)[-1],
            test_id=rule_id,
            severity=_SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "UNKNOWN"),
            confidence=str(metadata.get("confidence", "MEDIUM")).upper(),
            line=start,
            description=extra.get("message", ""),
            code=_snippet(result.get("path", ""), start, end),
            more_info=references[0] if isinstance(references, list) and references else "",
            cwe=_cwe(metadata),
            file=name_for(result.get("path", "")),
        ))
    return sort_and_number(findings)

def parse_semgrep_errors(report: dict, name_for) -> list:
    return [
        {"file": name_for(e.get("path", "")),
         "reason": e.get("message") or e.get("long_msg") or "unknown error"}
        for e in report.get("errors", [])
    ]

def scan_js_file(file_path: str, display_name: str = None,
                 config: str = DEFAULT_CONFIG) -> dict:
    """Scan one JavaScript file with Semgrep. The source code is analyzed, not executed."""
    path = Path(file_path)

    if not path.is_file():
        return _error("File not found.")
    if path.suffix.lower() not in JS_SUFFIXES:
        return _error("Only JavaScript files (.js, .jsx, .mjs, .cjs) are supported here.")

    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return _error(f"File is larger than {MAX_FILE_BYTES // 1024} KB.")

        shown_name = display_name or str(path)
        outcome = run_semgrep(path, config)
        if not outcome["ok"]:
            return _error(outcome["error"])

        report = outcome["report"]
        findings = parse_semgrep(report, lambda _p: shown_name,
                                short_ids=Path(config).is_file())
        scan_errors = [
            {"file": shown_name,
             "reason": e.get("message") or e.get("long_msg") or "unknown error"}
            for e in report.get("errors", [])
        ]

        # A file Semgrep could not parse must NOT be reported as "clean".
        if scan_errors and not findings:
            return _error("Semgrep could not analyze this file: " + scan_errors[0]["reason"])

        # No JS reachability model yet: "unknown" means "not modeled", NOT "safe".
        for finding in findings:
            finding["reachability"] = "unknown"
            finding["evidence"] = []

        warnings = []
        if size == 0:
            warnings.append("The file is empty; there was nothing to scan.")

        lines_scanned = len(path.read_text(encoding="utf-8", errors="replace").splitlines())

        return {
            "status": "success",
            "file": shown_name,
            "files_scanned": 1,
            "lines_scanned": lines_scanned,
            "total_issues": len(findings),
            "vulnerabilities": findings,
            "reachability": [],
            "scan_errors": scan_errors,
            "skipped_files": [],
            "warnings": warnings,
        }
    except Exception as error:  # last-resort guard so the UI never crashes
        return _error(str(error))