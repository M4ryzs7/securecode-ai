
import json
from pathlib import Path

from scanner import scan_file

BENCHMARK_DIR = Path("benchmark")
PROJECTS_DIR = BENCHMARK_DIR / "projects"
LABELS_FILE = BENCHMARK_DIR / "labels.json"

SKIP_DIRS = {
    ".git", ".venv", "venv", "env",
    "node_modules", "__pycache__", "site-packages", ".tox"
}


def load_labels():
    with LABELS_FILE.open(encoding="utf-8") as file:
        return json.load(file)


def collect_scanner_findings():
    findings = []

    for project_dir in sorted(PROJECTS_DIR.iterdir()):
        if not project_dir.is_dir():
            continue

        project = project_dir.name

        for path in project_dir.rglob("*.py"):
            relative_parts = path.relative_to(project_dir).parts

            if set(relative_parts[:-1]) & SKIP_DIRS:
                continue

            result = scan_file(
                str(path),
                display_name=Path(*relative_parts).as_posix()
            )

            if result["status"] != "success":
                print(f"Scan error: {project}/{path}: {result['error']}")
                continue

            for finding in result["vulnerabilities"]:
                findings.append({
                    "project": project,
                    "file": finding["file"],
                    "line": finding["line"],
                    "test_id": finding["test_id"],
                })

    return findings


def main():
    labels = load_labels()
    findings = collect_scanner_findings()

    label_map = {
        (x["project"], x["file"], x["line"], x["test_id"]): x["label"]
        for x in labels
    }

    tp = fp = fn = unlabelled = 0

    for finding in findings:
        key = (
            finding["project"],
            finding["file"],
            finding["line"],
            finding["test_id"],
        )

        label = label_map.get(key)

        if label == "TP":
            tp += 1
        elif label == "FP":
            fp += 1
        elif label is None:
            unlabelled += 1

    for entry in labels:
        key = (
            entry["project"],
            entry["file"],
            entry["line"],
            entry["test_id"],
        )

        if entry["label"] == "TP" and key not in {
            (
                f["project"], f["file"], f["line"], f["test_id"]
            )
            for f in findings
        }:
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    print("\n===== BENCHMARK RESULTS =====")
    print(f"Scanner findings: {len(findings)}")
    print(f"Matched TP:       {tp}")
    print(f"Matched FP:       {fp}")
    print(f"False Negatives:  {fn}")
    print(f"Unlabelled:       {unlabelled}")
    print(f"Precision:        {precision:.3f}")
    print(f"Recall:           {recall:.3f}")
    print(f"F1-score:         {f1:.3f}")


if __name__ == "__main__":
    main()
