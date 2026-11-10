"""Tests for scanner.py (runs the real Bandit; never executes the scanned code)."""

import subprocess

import pytest

import scanner
from scanner import scan_file, scan_zip, scan_upload, validate_fix_code

VULNERABLE = (
    "import subprocess\n"                      # 1
    "\n"
    'password = "admin123"\n'                  # 3
    "\n"
    "def run_command(user_input):\n"
    "    eval(user_input)\n"                   # 6
    "\n"
    "def execute_command(command):\n"
    "    subprocess.call(command, shell=True)\n"  # 9
)


def write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_vulnerable_file_findings(tmp_path):
    result = scan_file(write(tmp_path, "vuln.py", VULNERABLE))
    assert result["status"] == "success"
    lines = {f["test_id"]: f["line"] for f in result["vulnerabilities"]}
    assert lines["B404"] == 1
    assert lines["B105"] == 3
    assert lines["B307"] == 6
    assert lines["B602"] == 9
    assert result["total_issues"] == len(result["vulnerabilities"]) >= 4


def test_findings_have_required_fields_and_unique_ids(tmp_path):
    result = scan_file(write(tmp_path, "vuln.py", VULNERABLE))
    ids = [f["id"] for f in result["vulnerabilities"]]
    assert len(ids) == len(set(ids))
    for f in result["vulnerabilities"]:
        for key in ("id", "type", "test_id", "severity", "confidence",
                    "line", "description", "code", "more_info", "file"):
            assert key in f


def test_findings_sorted_most_severe_first(tmp_path):
    result = scan_file(write(tmp_path, "vuln.py", VULNERABLE))
    assert result["vulnerabilities"][0]["severity"] == "HIGH"


def test_clean_file_has_no_findings(tmp_path):
    result = scan_file(write(tmp_path, "clean.py", "def add(a, b):\n    return a + b\n"))
    assert result["status"] == "success"
    assert result["total_issues"] == 0
    assert result["vulnerabilities"] == []


def test_empty_file_succeeds_with_warning(tmp_path):
    result = scan_file(write(tmp_path, "empty.py", ""))
    assert result["status"] == "success"
    assert result["total_issues"] == 0
    assert any("empty" in w.lower() for w in result["warnings"])


def test_missing_file():
    result = scan_file("does_not_exist.py")
    assert result["status"] == "error"
    assert "not found" in result["error"].lower()


def test_non_python_file_rejected(tmp_path):
    result = scan_file(write(tmp_path, "notes.txt", "print('hi')"))
    assert result["status"] == "error"
    assert "python" in result["error"].lower()


def test_syntax_error_is_not_reported_as_clean(tmp_path):
    result = scan_file(write(tmp_path, "broken.py", "def oops(:\n    pass\n"))
    assert result["status"] == "error"


def test_display_name_is_used(tmp_path):
    result = scan_file(write(tmp_path, "tmpabc123.py", VULNERABLE), display_name="my_app.py")
    assert result["file"] == "my_app.py"
    assert {f["file"] for f in result["vulnerabilities"]} == {"my_app.py"}


def test_file_too_large(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 10)
    result = scan_file(write(tmp_path, "big.py", "x = 1\n" * 100))
    assert result["status"] == "error"
    assert "larger" in result["error"].lower()


def test_scanned_code_is_never_executed(tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"open(r'{marker}', 'w').write('x')\n"
    scan_file(write(tmp_path, "sideeffect.py", code))
    assert not marker.exists()


def test_bandit_not_installed(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="No module named bandit")
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    result = scan_file(write(tmp_path, "a.py", "x = 1\n"))
    assert result["status"] == "error"
    assert "pip install bandit" in result["error"]


def test_bandit_timeout(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="bandit", timeout=1)
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    result = scan_file(write(tmp_path, "a.py", "x = 1\n"))
    assert result["status"] == "error"
    assert "timed out" in result["error"].lower()


def test_scan_upload_rejects_unknown_type(tmp_path):
    result = scanner.scan_upload(write(tmp_path, "a.txt", "x"), "a.txt")
    assert result["status"] == "error"

def test_valid_fix_passes_bandit(tmp_path):
    code = (
        "import subprocess\n"
        "subprocess.run(['python', '--version'], "
        "shell=False, check=True, timeout=30)\n"
    )

    result = validate_fix_code(code, "B602")

    assert result["valid"] is True


def test_fix_rejected_if_original_finding_remains():
    code = (
        "import subprocess\n"
        "subprocess.call('echo hello', shell=True)\n"
    )

    result = validate_fix_code(code, "B602")

    assert result["valid"] is False
    assert "original" in result["reason"].lower()


def test_fix_rejected_if_syntax_is_invalid():
    result = validate_fix_code(
        "def broken(:\n    pass\n",
        "B602"
    )

    assert result["valid"] is False
    assert "syntax" in result["reason"].lower()

def test_fix_rejected_if_new_high_finding_is_introduced():
    code = (
        "import subprocess\n"
        "import pickle\n"
        "subprocess.run(['python', '--version'], "
        "shell=False, check=True, timeout=30)\n"
        "pickle.loads(data)\n"
    )

    result = validate_fix_code(code, "B602")

    assert result["valid"] is False
    assert "HIGH or MEDIUM" in result["reason"]

def test_scan_file_includes_reachability_results(tmp_path):
    code = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/search")\n'
        "def search():\n"
        "    eval('1 + 1')\n"
        '    return "OK"\n'
    )

    result = scan_file(write(tmp_path, "app.py", code))

    assert result["status"] == "success"
    assert "reachability" in result
    assert len(result["reachability"]) == 1
    assert result["reachability"][0]["route"] == "/search"

def test_scan_file_includes_reachability_results(tmp_path):
    code = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/search")\n'
        "def search():\n"
        "    eval('1 + 1')\n"
        '    return "OK"\n'
    )

    result = scan_file(write(tmp_path, "app.py", code))

    assert result["status"] == "success"
    assert "reachability" in result
    assert len(result["reachability"]) == 1
    assert result["reachability"][0]["route"] == "/search"

def test_scan_zip_includes_reachability_results(tmp_path):
    import zipfile

    code = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        '@app.route("/search")\n'
        "def search():\n"
        "    user_input = request.args.get('q')\n"
        "    eval(user_input)\n"
        '    return "OK"\n'
    )

    zip_path = tmp_path / "project.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("app.py", code)

    result = scan_zip(str(zip_path))

    assert result["status"] == "success"
    assert "reachability" in result
    assert len(result["reachability"]) == 1

    finding = result["reachability"][0]

    assert finding["route"] == "/search"
    assert finding["sink"]["name"] == "eval"
    assert finding["source"]["name"] == "request.args.get"
    assert finding["file"] == "app.py"