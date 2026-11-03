# 🛡️ SecureCode AI

**AI-Powered Python Code Security Scanner**

SecureCode AI is a local AI-assisted security analysis tool that scans Python source code and Python project ZIP files to identify potentially risky coding patterns.

It combines **Bandit static analysis**, a curated security remediation knowledge base, and a locally running **Qwen 2.5 1.5B** language model to provide understandable explanations and practical remediation guidance.

The goal is to help developers identify potential security issues, understand their impact, and learn how to improve their code.

## ✨ Features

- **Python File Scanning:** Upload and scan individual `.py` files.
- **ZIP Project Scanning:** Upload ZIP archives containing Python projects and scan multiple Python files.
- **Static Security Analysis:** Uses Bandit to identify potentially insecure code patterns.
- **AI-Powered Explanations:** Uses a local Qwen model through Ollama to explain security findings.
- **Curated Remediation Guidance:** Provides predefined explanations, potential impacts, recommendations, and illustrative code examples for supported Bandit findings.
- **Severity Classification:** Displays findings according to HIGH, MEDIUM, and LOW severity.
- **Security Reports:** Download scan results in Markdown and JSON formats.
- **Safe ZIP Processing:** Applies archive validation and extraction limits to reduce ZIP-related security risks.
- **Privacy-Focused:** Code analysis runs locally; uploaded source code is not intentionally sent to an external AI API.

## 🏗️ How It Works

1. The user uploads a Python file or a ZIP archive containing a Python project.
2. The application validates the uploaded file.
3. Bandit performs static security analysis without executing the uploaded source code.
4. The application collects and classifies the findings.
5. The remediation knowledge base provides security guidance for supported findings.
6. The local Qwen model generates additional explanations.
7. The results are displayed in an interactive dashboard.
8. The user can download a Markdown or JSON report.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Streamlit | Interactive web interface |
| Bandit | Static Python security analysis |
| Ollama | Local LLM execution |
| Qwen 2.5 1.5B | AI-generated explanations |
| Requests | Communication with the Ollama API |
| Pytest | Automated testing |

## 📁 Project Structure

```text
securecode-ai/
│
├── app.py                  # Streamlit application
├── scanner.py              # Bandit scanning functionality
├── analyzer.py             # AI explanation and analysis
├── remediation_kb.py       # Curated security guidance
├── ollama_client.py        # Local Ollama integration
├── safe_zip.py             # Secure ZIP processing
├── report.py               # Markdown and JSON reports
│
├── requirements.txt        # Python dependencies
├── vulnerable_sample.py    # Example vulnerable Python file
├── smoke_test.py            # Local integration smoke test
│
├── test_analyzer.py
├── test_ollama.py
├── test_remediation_kb.py
├── test_report.py
├── test_scanner.py
├── test_zip_scanner.py
│
└── .streamlit/
    └── config.toml
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

**Windows:**
```powershell
.venv\Scripts\activate
```

**macOS/Linux:**
```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install the local AI model

Make sure Ollama is running, then execute:

```bash
ollama pull qwen2.5:1.5b
```

### 5. Run the application

```bash
streamlit run app.py
```

The application will open in your browser, usually at:

```text
http://localhost:8501
```

## 🚀 How to Use

1. Open SecureCode AI in your browser.
2. Upload a Python `.py` file or a ZIP archive containing a Python project.
3. Click **Scan** to start static analysis.
4. Review the detected findings, severity levels, affected files, and line numbers.
5. Request AI explanations and remediation guidance.
6. Download the results as a Markdown or JSON report.

## 🧪 Running Tests

Run the automated test suite:

```bash
python -m pytest -q
```

The current project test suite contains **139 passing tests** in the development environment.

For a local integration check with Ollama:

```bash
python smoke_test.py
```

## ⚠️ Limitations

- Bandit identifies potentially risky code patterns; it does not prove that a vulnerability is exploitable.
- Static analysis cannot fully understand application context or determine whether every input is attacker-controlled.
- AI-generated explanations are unverified and should be reviewed.
- Curated remediation examples are illustrative and must be adapted and tested before use.
- A clean scan does not guarantee that a project is completely secure.
- The current implementation focuses on Python source code.

## 🔒 Security and Privacy

- Uploaded Python code is analyzed without being executed.
- AI explanations are generated using a locally running Ollama model.
- ZIP archives are subject to validation and extraction limits.
- Suggested code changes are not automatically applied to uploaded files.

## 👩‍💻 Author

**M4ryzs7**

GitHub: [https://github.com/M4ryzs7](https://github.com/M4ryzs7)

---

*SecureCode AI — Making Python code security analysis more accessible with static analysis and local AI.*