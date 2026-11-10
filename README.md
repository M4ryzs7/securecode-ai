# 🛡️ SecureCode AI

**AI-Assisted Python Code Security Scanner**

SecureCode AI is a local AI-assisted security analysis tool that scans individual Python source files and Python project ZIP archives to identify potentially risky coding patterns.

It combines **Bandit static analysis**, a curated security remediation knowledge base, a custom Flask Reachability Analysis module, and a locally running **Qwen 2.5 1.5B** language model through Ollama.

The project helps developers identify potential security issues, understand their implications, and receive evidence-based explanations and remediation guidance.

## ✨ Features

- **Python File Scanning:** Scan individual Python files.
- **ZIP Project Scanning:** Upload and scan Python projects contained in ZIP archives.
- **Static Security Analysis:** Uses Bandit to identify potentially insecure coding patterns.
- **Flask Reachability Analysis:** Discovers supported Flask routes and analyzes reachable functions for selected dangerous operations.
- **Source and Sink Detection:** Identifies selected user-input sources and dangerous sinks, including `request.args.get`, `eval`, and certain command-execution calls.
- **Call Graph Analysis:** Tracks direct function calls and analyzes reachable functions from discovered Flask routes.
- **AI-Powered Explanations:** Generates additional explanations using a local Ollama model.
- **AI Security Triage:** Classifies findings as likely true positive, likely false positive, or uncertain.
- **Evidence-Based Validation:** Rejects certain AI responses that contain unsupported security claims or contradict explicit code evidence.
- **Curated Remediation Guidance:** Provides predefined explanations, potential impacts, recommendations, and illustrative examples.
- **Suggested Fix Validation:** Checks suggested code snippets using Python AST parsing and Bandit scanning before displaying them.
- **Severity Classification:** Preserves Bandit's HIGH, MEDIUM, and LOW severity classifications.
- **Security Reports:** Exports scan results in Markdown and JSON formats, including Reachability Analysis results.
- **Safe ZIP Processing:** Applies archive validation and extraction limits.
- **Local AI Processing:** Uses Ollama locally rather than an external AI API.
- **Automated Testing:** Includes a pytest test suite and GitHub Actions CI workflow.

## 🏗️ Architecture

The application follows this general workflow:

1. The user uploads a Python file or ZIP archive.
2. The application validates the uploaded content.
3. Bandit performs static security analysis without executing the uploaded source code.
4. For Python files, the Reachability Analysis module examines supported Flask routes, function call relationships, selected input sources, and dangerous sinks.
5. For ZIP archives, the application safely extracts eligible Python files and aggregates their Reachability Analysis results.
6. Findings are collected and classified.
7. The remediation knowledge base provides curated security guidance.
8. The local LLM generates structured explanations and triage assessments.
9. AI responses are validated before being accepted.
10. Suggested fixes undergo separate syntax and Bandit checks.
11. Results are displayed in the Streamlit dashboard.
12. Users can download Markdown or JSON reports.

### Reachability Analysis

The Reachability Analysis module uses Python AST parsing to inspect source code without executing it.

Its current capabilities include:

- Discovering supported Flask routes using decorators such as `@app.route` and selected HTTP method decorators.
- Building a call graph from direct function calls.
- Traversing reachable functions from discovered route handlers.
- Detecting selected dangerous sinks, such as `eval`, `exec`, and certain command-execution calls.
- Detecting selected user-input sources, including `request.args.get`.
- Tracking simple variable aliases in supported cases.
- Associating detected sources and sinks with their routes and source files.

**Important limitations:**

Reachability Analysis is a prototype, not a comprehensive taint-analysis engine. It does not cover all Flask routing patterns, cross-file data flows, complex aliases, dynamic dispatch, or every possible source and sink. A reachable dangerous sink does not by itself prove exploitability. Missing results do not prove that an application is safe.

### LLM Reliability

The AI analysis layer includes several reliability mechanisms:

- Structured JSON responses validated against a JSON Schema.
- Restricted triage categories.
- Prompt instructions requiring evidence-based explanations.
- Validation against unsupported security claims.
- Explicit evidence consistency checks for certain code contradictions.
- Rejection of invalid or inconsistent AI responses.

AI-generated assessments remain advisory and do not modify Bandit's original findings, severity, or confidence.

### Suggested Fix Validation

Suggested fixes are checked using:

- Python AST parsing for syntax validation.
- Bandit scanning of the proposed snippet.
- Checks for persistence of the original finding.
- Checks for newly introduced HIGH or MEDIUM findings.

Validation is performed on an isolated snippet. Passing these checks does not prove that the proposed fix is safe or correct in the complete application. Fixes are never automatically applied.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Streamlit | Interactive web interface |
| Bandit | Static Python security analysis |
| Python AST | Source-code and reachability analysis |
| Ollama | Local LLM execution |
| Qwen 2.5 1.5B | AI-generated explanations |
| Requests | Communication with the Ollama API |
| Pytest | Automated testing |
| GitHub Actions | Continuous Integration |

## 📁 Project Structure

```text
securecode-ai/
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── .streamlit/
│   └── config.toml
│
├── evaluation/
│   ├── cases.json
│   └── run_evaluation.py
│
├── app.py
├── scanner.py
├── reachability.py
├── analyzer.py
├── remediation_kb.py
├── ollama_client.py
├── safe_zip.py
├── report.py
│
├── requirements.txt
├── vulnerable_sample.py
├── smoke_test.py
│
├── test_analyzer.py
├── test_ollama.py
├── test_remediation_kb.py
├── test_report.py
├── test_scanner.py
├── test_reachability.py
└── test_zip_scanner.py
```

## ⚙️ Installation and Setup

### Prerequisites

- Python 3.10 or newer
- [Ollama](https://ollama.com/)
- Git

### 1. Clone the repository

```bash
git clone https://github.com/M4ryzs7/securecode-ai.git
cd securecode-ai
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it:

**Windows PowerShell:**

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The commands below can be run without activating the virtual environment.

**macOS/Linux:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Install the local AI model

```bash
ollama pull qwen2.5:1.5b
```

Make sure Ollama is running before starting AI-powered analysis.

### 4. Run the application

**Windows PowerShell:**

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

**macOS/Linux:**

```bash
streamlit run app.py
```

The application is usually available at:

```text
http://localhost:8501
```

## 🔧 Ollama Configuration

SecureCode AI supports environment-based Ollama configuration.

Default settings:

| Variable | Default |
|---|---|
| `OLLAMA_MODEL` | `qwen2.5:1.5b` |
| `OLLAMA_BASE_URL` | `http://localhost:11434` |

**Windows PowerShell example:**

```powershell
$env:OLLAMA_MODEL = "qwen2.5:1.5b"
$env:OLLAMA_BASE_URL = "http://localhost:11434"
```

These variables allow users to select an installed Ollama model and configure the Ollama server URL without modifying the source code.

## 🚀 How to Use

1. Open SecureCode AI in your browser.
2. Upload a Python `.py` file or a ZIP archive.
3. Start the scan.
4. Review detected findings, severity levels, affected files, and line numbers.
5. Review the Reachability Analysis section, when supported results are detected.
6. Review available curated remediation guidance.
7. Request AI explanations and triage assessments when Ollama is available.
8. Review suggested fixes when available.
9. Download the results as Markdown or JSON reports.

## 🧪 Running Tests

Run the complete automated test suite:

```bash
python -m pytest -q
```

**Current verified test status: 173 passed.**

For a local integration check with Ollama:

```bash
python smoke_test.py
```

The integration check requires a running Ollama server and the configured model.

## 📊 LLM Evaluation

The project includes an evaluation framework with 10 predefined security-analysis cases.

Run the evaluation:

```bash
python evaluation/run_evaluation.py
```

The evaluation measures structured response validity, evidence consistency, and triage accuracy.

### Current Evaluation Results

Model: `qwen2.5:1.5b`

| Metric | Result |
|---|---:|
| Valid response format rate | 90% |
| Evidence consistency rate | 88.89% |
| Triage accuracy | 50% |

These results are from a 10-case evaluation and should not be interpreted as a comprehensive benchmark.

The evidence consistency checker currently covers explicit shell argument contradictions. It is not a general semantic verification system.

## 🔄 Continuous Integration

SecureCode AI uses GitHub Actions to automatically run the pytest suite.

Workflow file:

```text
.github/workflows/tests.yml
```

The workflow runs on:

- Pushes to `main`.
- Pull requests targeting `main`.

The CI pipeline:

1. Checks out the repository.
2. Sets up Python 3.11.
3. Installs project dependencies.
4. Runs the automated test suite.

This helps detect regressions before changes are integrated into the main branch.

## ⚠️ Limitations

- Bandit identifies potentially risky coding patterns; it does not prove that a vulnerability is exploitable.
- Reachability Analysis supports a limited set of Flask route patterns, sources, sinks, and direct function calls.
- Reachability results indicate possible code paths and do not prove exploitability.
- Static analysis cannot fully understand application context or determine whether every input is attacker-controlled.
- AI-generated triage and explanations are advisory and may be incorrect.
- Evidence consistency validation covers only a limited set of explicit contradictions.
- Suggested fixes are checked as isolated snippets, not as complete project patches.
- Passing syntax and Bandit checks does not guarantee that a suggested fix is secure.
- Curated remediation examples are illustrative and must be adapted and tested.
- A clean scan does not guarantee that a project is completely secure.
- The current implementation focuses on Python source code.

## 🔒 Security and Privacy

- Uploaded Python source code is analyzed without being executed by the scanner.
- AI explanations are generated through a locally running Ollama model.
- ZIP archives are subject to validation and extraction limits.
- Suggested code changes are not automatically applied.
- AI assessments do not replace manual security review.

## 👩‍💻 Author

**Maryam Salahli**

GitHub: [M4ryzs7](https://github.com/M4ryzs7)

---

*SecureCode AI — Making Python code security analysis more accessible through static analysis and local AI.*
