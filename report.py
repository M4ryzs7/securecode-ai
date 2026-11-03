"""report.py - Builds downloadable scan reports (Markdown and JSON)."""

import json
import re
from datetime import datetime, timezone

DISCLAIMER = (
    "This report combines Bandit (pattern-based static analysis) with curated guidance and "
    "optional explanations from a small local language model. Findings are potential issues, "
    "not confirmed vulnerabilities. The AI text is unverified. Code examples are illustrations "
    "to adapt and test. Nothing was changed in your code."
)


def _fence(text: str) -> str:
    """Pick a code fence longer than any run of backticks inside the text."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _code_block(text: str, language: str = "python") -> str:
    fence = _fence(text)
    return f"{fence}{language}\n{text.rstrip()}\n{fence}"


def build_json_report(scan_result: dict, analysis: dict = None) -> str:
    """Bandit results and AI interpretation are kept in separate sections."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": DISCLAIMER,
        "bandit": scan_result,
        "interpretation": analysis if analysis and analysis.get("status") == "success" else None,
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def build_markdown_report(scan_result: dict, analysis: dict = None) -> str:
    lines = ["# SecureCode AI - Scan Report", ""]
    lines.append(f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"- Target: `{scan_result.get('file', 'unknown')}`")
    lines.append(f"- Files scanned: {scan_result.get('files_scanned', 1)}")
    lines.append(f"- Total findings: {scan_result.get('total_issues', 0)}")
    lines += ["", f"> {DISCLAIMER}", ""]

    by_id = {}
    if analysis and analysis.get("status") == "success":
        by_id = {a["id"]: a for a in analysis.get("analyses", [])}
        lines += ["## Summary", "", analysis.get("summary", ""), ""]

    findings = scan_result.get("vulnerabilities", [])
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No Bandit findings detected.")

    for finding in findings:
        lines.append(
            f"### {finding['id']} - {finding['test_id']} {finding['type']} "
            f"({finding['severity']})"
        )
        lines.append("")
        lines.append("**Bandit result**")
        lines.append("")
        lines.append(f"- File: `{finding.get('file', '')}`, line {finding.get('line')}")
        lines.append(f"- Severity: {finding['severity']}   Confidence: {finding['confidence']}")
        if finding.get("cwe"):
            lines.append(f"- {finding['cwe']}")
        lines.append(f"- Message: {finding['description']}")
        lines.append("")
        lines.append(_code_block(finding.get("code", "")))
        lines.append("")

        item = by_id.get(finding["id"])
        if item:
            lines.append("**Guidance (curated rules)**" if item["curated"]
                         else "**Guidance (no curated rule for this test ID)**")
            lines.append("")
            lines.append(f"- Classification: {item['category_label']}")
            lines.append(f"- What it means: {item['explanation']}")
            lines.append(f"- Potential impact: {item['impact']}")
            lines.append(f"- Recommendation: {item['recommendation']}")
            for note in item["notes"]:
                lines.append(f"- Note: {note}")
            if item["fixed_code"]:
                lines += ["", "Illustrative example (adapt and test; not applied to your code):", "",
                          _code_block(item["fixed_code"])]
            if item["ai_status"] == "ok":
                lines += ["", f"**AI explanation ({analysis.get('model', 'local model')}, unverified)**",
                          "", item["ai_explanation"]]
            lines.append("")

    skipped = scan_result.get("skipped_files", [])
    if skipped:
        lines += ["## Skipped files", ""]
        lines += [f"- `{s['name']}`: {s['reason']}" for s in skipped[:200]]
        lines.append("")

    errors = scan_result.get("scan_errors", [])
    if errors:
        lines += ["## Files Bandit could not analyze", ""]
        lines += [f"- `{e['file']}`: {e['reason']}" for e in errors]
        lines.append("")

    return "\n".join(lines)
