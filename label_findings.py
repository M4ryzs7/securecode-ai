"""
label_findings.py - Manually label Bandit findings as real (TP) or false alarm (FP).

Usage (from the repo root):
    python label_findings.py benchmark/projects/vuln_app_1
    python label_findings.py benchmark/projects/vuln_app_1 --skip-tests
    python label_findings.py benchmark/projects/vuln_app_1 --show-hints

Keys at the prompt:
    t [note]   real vulnerability (true positive)
    f [note]   false alarm (false positive)
    s          skip for now (not saved, shown again next run)
    q          save and quit

Labels are saved to benchmark/labels.json after EVERY answer, so you can stop any
time and continue later. Already-labeled findings are not shown again.

By default the tool's own verdict (reachability / evidence) is HIDDEN, so your
labels do not depend on the thing being measured. Use --show-hints only for debugging.
"""

import argparse
import json
import sys
from pathlib import Path

from scanner import scan_file

LABELS_PATH = Path("benchmark") / "labels.json"
MAX_FILE_BYTES = 1 * 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "site-packages", ".tox"}
TEST_DIR_NAMES = {"test", "tests"}


def load_labels() -> list:
    if LABELS_PATH.exists():
        return json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    return []


def save_labels(labels: list) -> None:
    LABELS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = LABELS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(labels, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(LABELS_PATH)   # atomic-ish: never leaves a half-written file


def key_of(entry: dict) -> tuple:
    return (entry["project"], entry["file"], entry["line"], entry["test_id"])


def python_files(project_dir: Path, skip_tests: bool):
    for path in sorted(project_dir.rglob("*.py")):
        relative = path.relative_to(project_dir)
        parts = set(relative.parts[:-1])
        if parts & SKIP_DIRS:
            continue
        if skip_tests and (parts & TEST_DIR_NAMES or relative.name.startswith("test_")):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            print(f"  (skipped, too large: {relative.as_posix()})")
            continue
        yield path, relative.as_posix()


def collect_findings(project_dir: Path, skip_tests: bool) -> list:
    project = project_dir.name
    findings = []
    for path, relative in python_files(project_dir, skip_tests):
        result = scan_file(str(path), display_name=relative)
        if result["status"] != "success":
            print(f"  (could not scan {relative}: {result.get('error')})")
            continue
        for finding in result["vulnerabilities"]:
            finding["project"] = project
            findings.append(finding)
    findings.sort(key=lambda f: (f["file"], f["line"] or 0))
    return findings


def show(finding: dict, number: int, total: int, show_hints: bool) -> None:
    print("\n" + "=" * 78)
    print(f"[{number}/{total}] {finding['project']} :: {finding['file']}:{finding['line']}")
    print(f"{finding['test_id']} {finding['type']}  "
          f"(severity={finding['severity']}, confidence={finding['confidence']}, {finding['cwe']})")
    print(finding["description"])
    print("-" * 78)
    print(finding["code"].rstrip())
    if show_hints:
        print("-" * 78)
        print(f"HINT reachability = {finding['reachability']}")
        for hit in finding.get("evidence", []):
            source = hit.get("source")
            via = f"{source['name']} (var {source['variable']}, line {source['line']})" if source else "no user input proven"
            print(f"  route {hit['route']} -> {hit['sink']['name']} | {via}")
    print("=" * 78)


def ask() -> tuple:
    while True:
        raw = input("label [t/f/s/q] (optional note after t or f): ").strip()
        if not raw:
            continue
        choice, _, note = raw.partition(" ")
        choice = choice.lower()
        if choice in {"t", "f", "s", "q"}:
            return choice, note.strip()
        print("Please type t, f, s or q.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("project_dir", help="folder of ONE project to label")
    parser.add_argument("--skip-tests", action="store_true", help="ignore test files and test folders")
    parser.add_argument("--show-hints", action="store_true", help="show the tool's own reachability verdict (biases labels)")
    args = parser.parse_args()

    project_dir = Path(args.project_dir)
    if not project_dir.is_dir():
        print(f"Not a folder: {project_dir}")
        return 1

    labels = load_labels()
    done = {key_of(entry) for entry in labels}

    print(f"Scanning {project_dir} ...")
    findings = collect_findings(project_dir, args.skip_tests)
    todo = [f for f in findings if (f["project"], f["file"], f["line"], f["test_id"]) not in done]
    print(f"{len(findings)} findings, {len(findings) - len(todo)} already labeled, {len(todo)} to label.")

    for number, finding in enumerate(todo, start=1):
        show(finding, number, len(todo), args.show_hints)
        choice, note = ask()
        if choice == "q":
            break
        if choice == "s":
            continue
        labels.append({
            "project": finding["project"],
            "file": finding["file"],
            "line": finding["line"],
            "test_id": finding["test_id"],
            "label": "TP" if choice == "t" else "FP",
            "note": note,
        })
        save_labels(labels)

    tp = sum(1 for entry in labels if entry["label"] == "TP")
    print(f"\nSaved. Total labels so far: {len(labels)} (TP={tp}, FP={len(labels) - tp}) -> {LABELS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
