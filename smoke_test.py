"""
Manual end-to-end check against your REAL Ollama (not collected by pytest).
Run:  python smoke_test.py
"""
from analyzer import analyze_vulnerabilities
from ollama_client import check_ollama
from scanner import scan_file

print("Ollama:", check_ollama()["message"])
scan = scan_file("vulnerable_sample.py")
print("Scan:", scan["status"], "-", scan.get("total_issues"), "findings")

analysis = analyze_vulnerabilities(scan, use_ai=True)
print("\n", analysis.get("summary", analysis.get("error")))
for warning in analysis.get("warnings", []):
    print("WARNING:", warning)

for item in analysis.get("analyses", []):
    print("\n" + "-" * 60)
    print(f"{item['id']} {item['test_id']} {item['type']} | {item['severity']} | "
          f"{item['file']}:{item['line']}")
    print("Class:         ", item["category_label"])
    print("Impact:        ", item["impact"])
    print("Recommendation:", item["recommendation"])
    if item["fixed_code"]:
        print("Example code:\n" + item["fixed_code"])
    print("AI status:     ", item["ai_status"], item["ai_note"])
    if item["ai_explanation"]:
        print("AI explanation:", item["ai_explanation"])
