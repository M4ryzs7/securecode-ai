import json
import sys
from pathlib import Path

# Add the project root to Python's import path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analyzer import (
    AI_RESPONSE_SCHEMA,
    build_prompt,
    parse_ai_response,
    validate_evidence_consistency,
)

from ollama_client import MODEL_NAME, check_ollama, query_ollama


BASE_DIR = Path(__file__).resolve().parent
CASES_FILE = BASE_DIR / "cases.json"
RESULTS_FILE = BASE_DIR / "results.json"


def run_evaluation():
    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))

    connection = check_ollama()

    if not connection.get("available") or not connection.get("model_installed"):
        raise RuntimeError(connection.get("message", "Ollama is unavailable"))

    results = []

    
    for index, case in enumerate(cases, start=1):
        print(f"[{index}/{len(cases)}] Evaluating {case['id']}...")

        raw_response = ""
        parsed = None
        error = None
        json_valid = False
        evidence_consistent = None

        try:
            ollama_result = query_ollama(
                build_prompt(case),
                response_schema=AI_RESPONSE_SCHEMA,
            )

            if not ollama_result.get("ok"):
                error = (
                    f"Ollama {ollama_result.get('error_kind')}: "
                    f"{ollama_result.get('error')}"
                )
            else:
                raw_response = ollama_result.get("text", "")

                parsed, error = parse_ai_response(
                    raw_response,
                    case["test_id"],
                )

                json_valid = parsed is not None

                if parsed is not None:
                    evidence_consistent, evidence_error = (
                        validate_evidence_consistency(case, parsed)
                    )

                    if not evidence_consistent:
                        error = (
                            "Evidence consistency check failed: "
                            f"{evidence_error}"
                        )
                        parsed = None

        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

        actual_triage = parsed["triage"] if parsed else None

        results.append({
            "id": case["id"],
            "test_id": case["test_id"],
            "category": case["category"],
            "expected_triage": case["expected_triage"],
            "actual_triage": actual_triage,
            "triage_correct": (
                actual_triage == case["expected_triage"]
                if actual_triage is not None else False
            ),
            "json_valid": json_valid,
            "evidence_consistent": evidence_consistent,
            "valid_response": parsed is not None,
            "validation_error": error,
            "triage_reason": parsed["triage_reason"] if parsed else None,
            "explanation": parsed["explanation"] if parsed else None,
        })
    
    total = len(results)

    json_valid_count = sum(r["json_valid"] for r in results)

    evidence_checked = [
        r for r in results
        if r["evidence_consistent"] is not None
    ]

    evidence_consistent_count = sum(
        r["evidence_consistent"] for r in evidence_checked
    )

    valid_count = sum(r["valid_response"] for r in results)
    correct_count = sum(r["triage_correct"] for r in results)

    metrics = {
        "model": MODEL_NAME,
        "total_cases": total,
        "valid_json_rate": round(json_valid_count / total * 100, 2),
        "evidence_consistency_rate": (
            round(
                evidence_consistent_count / len(evidence_checked) * 100,
                2,
            )
            if evidence_checked else 0
        ),
        "triage_accuracy": round(correct_count / total * 100, 2),
        "correct_triage": correct_count,
        "valid_responses": valid_count,
    }

    output = {
        "metrics": metrics,
        "results": results,
    }

    RESULTS_FILE.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n=== EVALUATION SUMMARY ===")
    for key, value in metrics.items():
        print(f"{key}: {value}")

    print(f"\nDetailed results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    run_evaluation()
