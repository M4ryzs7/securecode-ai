# Benchmark

Hand-labeled findings used to evaluate the AI triage (`python evaluate_ai.py`).
Labels are in `labels.json`; model outputs are in `ai_results_*.json`.

The project folders are **not** included in this repository. To reproduce the
benchmark, obtain each project from its source and place it under
`benchmark/projects/<name>/`.

| Folder | Project | Source | Obtained | License |
|---|---|---|---|---|
| vuln_app_1 | `vulnerable_sample.py` | this repository | n/a | n/a |
| vuln_app_2 | Vulnerable Flask App | https://github.com/videvelopers/Vulnerable-Flask-App | commit 155a9d4 | GPL-3.0 |
| vuln_app_3 | Extremely Vulnerable Flask App | https://github.com/manuelz120/extremely-vulnerable-flask-app | commit d5d8875 | GPL-30 |
| vuln_app_4 | DVFA: Damn Vulnerable Flask App | https://github.com/maximilianmarx/DVFA | commit 6f6286f | no license file found |

All labels (true / false positive) were assigned by one person, the author of
this repository. The benchmark covers Python (Bandit) findings only.