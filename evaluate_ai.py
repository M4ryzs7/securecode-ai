
import json
from pathlib import Path

from scanner import scan_file
from analyzer import analyze_vulnerabilities
from ollama_client import MODEL_NAME

BENCHMARK_DIR = Path("benchmark")
PROJECTS_DIR = BENCHMARK_DIR / "projects"
LABELS_FILE = BENCHMARK_DIR / "labels.json"
OUTPUT_FILE = BENCHMARK_DIR / f"ai_results_{MODEL_NAME.replace(':', '_')}.json"

SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules",
    "__pycache__", "site-packages", ".tox"
}


def load_labels():
    with LABELS_FILE.open(encoding="utf-8") as file:
        return json.load(file)


def main():
    labels = load_labels()
    label_map = {
        (x["project"], x["file"], x["line"], x["test_id"]): x["label"]
        for x in labels
    }

    results = []

    for project_dir in sorted(PROJECTS_DIR.iterdir()):
        if not project_dir.is_dir():
            continue

        project = project_dir.name
        print(f"\nScanning project: {project}")

        for path in sorted(project_dir.rglob("*.py")):
            relative = path.relative_to(project_dir)
            if set(relative.parts[:-1]) & SKIP_DIRS:
                continue

            relative_name = relative.as_posix()

            scan = scan_file(
                str(path),
                display_name=relative_name
            )

            if scan["status"] != "success":
                print(f"  Scan error: {relative_name}: {scan['error']}")
                continue

            if not scan["vulnerabilities"]:
                continue

            analysis = analyze_vulnerabilities(
                scan,
                use_ai=True,
                max_ai_findings=100
            )

            if analysis["status"] != "success":
                print(f"  Analysis error: {relative_name}")
                continue

            for finding, item in zip(
                scan["vulnerabilities"],
                analysis["analyses"]
            ):
                key = (
                    project,
                    finding["file"],
                    finding["line"],
                    finding["test_id"]
                )

                results.append({
                    "project": project,
                    "file": finding["file"],
                    "line": finding["line"],
                    "test_id": finding["test_id"],
                    "human_label": label_map.get(key),
                    "ai_status": item["ai_status"],
                    "ai_triage": item["ai_triage"],
                    "ai_triage_reason": item["ai_triage_reason"],
                    "ai_explanation": item["ai_explanation"],
                    "ai_note": item["ai_note"],
                })

                print(
                    f"  {finding['test_id']} | "
                    f"Human: {label_map.get(key)} | "
                    f"AI: {item['ai_triage']} | "
                    f"Status: {item['ai_status']}"
                )

    # Evaluate only valid, decisive AI classifications.
    tp = fp = fn = tn = 0
    uncertain = rejected = unavailable = unlabelled = 0

    for result in results:
        human = result["human_label"]
        status = result["ai_status"]
        prediction = result["ai_triage"]

        if human not in {"TP", "FP"}:
            unlabelled += 1
            continue

        if status == "rejected":
            rejected += 1
            continue
        if status != "ok":
            unavailable += 1
            continue

        if prediction == "uncertain":
            uncertain += 1
            continue

        predicted_positive = prediction == "likely_true_positive"
        actual_positive = human == "TP"

        if predicted_positive and actual_positive:
            tp += 1
        elif predicted_positive and not actual_positive:
            fp += 1
        elif not predicted_positive and actual_positive:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )
    total_labelled = sum(
        1 for r in results if r["human_label"] in {"TP", "FP"}
    )
    evaluated = tp + fp + fn + tn
    coverage = evaluated / total_labelled if total_labelled else 0

    report = {
        "model": MODEL_NAME,
        "total_findings": len(results),
        "confusion_matrix": {
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "TN": tn
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "coverage": round(coverage, 4)
        },
        "other": {
            "uncertain": uncertain,
            "rejected": rejected,
            "unavailable": unavailable,
            "unlabelled": unlabelled
        },
        "results": results
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("\n===== AI BENCHMARK RESULTS =====")
    print(f"Model:       {MODEL_NAME}")
    print(f"Findings:    {len(results)}")
    print(f"TP:          {tp}")
    print(f"FP:          {fp}")
    print(f"FN:          {fn}")
    print(f"TN:          {tn}")
    print(f"Uncertain:   {uncertain}")
    print(f"Rejected:    {rejected}")
    print(f"Unavailable: {unavailable}")
    print(f"Coverage:    {coverage:.3f}")
    print(f"Precision:   {precision:.3f}")
    print(f"Recall:      {recall:.3f}")
    print(f"F1-score:    {f1:.3f}")
    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
