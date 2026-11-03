"""Tests for ZIP upload handling: safe extraction and multi-file scanning."""

import zipfile

import pytest

import safe_zip
from scanner import scan_zip

VULN = 'import subprocess\nsubprocess.call(cmd, shell=True)\n'


def make_zip(tmp_path, entries, name="project.zip"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        for entry_name, data in entries.items():
            zf.writestr(entry_name, data)
    return str(path)


def test_scans_multiple_files_and_reports_file_names(tmp_path):
    zip_path = make_zip(tmp_path, {
        "app/main.py": "print('hello')\n",
        "app/utils/shell.py": VULN,
        "README.md": "# docs",
    })
    result = scan_zip(zip_path)
    assert result["status"] == "success"
    assert result["files_scanned"] == 2
    files = {f["file"] for f in result["vulnerabilities"]}
    assert files == {"app/utils/shell.py"}
    assert any(s["name"] == "README.md" for s in result["skipped_files"])


@pytest.mark.parametrize("bad_name", [
    "../evil.py", "a/../../evil.py", "/abs/evil.py", "C:/evil.py",
    "..\\evil.py", "a\\..\\..\\evil.py", ".. /evil.py",
])
def test_path_traversal_rejects_archive(tmp_path, bad_name):
    zip_path = make_zip(tmp_path, {"ok.py": "x = 1\n", bad_name: "x = 2\n"})
    result = scan_zip(zip_path)
    assert result["status"] == "error"
    assert "rejected" in result["error"].lower()
    assert not (tmp_path / "evil.py").exists()


def test_archive_without_python_files(tmp_path):
    result = scan_zip(make_zip(tmp_path, {"notes.txt": "hello", "img.png": b"\x89PNG"}))
    assert result["status"] == "error"
    assert "no python" in result["error"].lower()


def test_not_a_zip(tmp_path):
    fake = tmp_path / "fake.zip"
    fake.write_text("this is not a zip")
    result = scan_zip(str(fake))
    assert result["status"] == "error"
    assert "not a valid zip" in result["error"].lower()


def test_missing_zip():
    assert scan_zip("nope.zip")["status"] == "error"


def test_ignored_folders_are_skipped(tmp_path):
    result = scan_zip(make_zip(tmp_path, {
        "src/app.py": "x = 1\n",
        ".venv/lib/site-packages/bad.py": VULN,
    }))
    assert result["status"] == "success"
    assert result["files_scanned"] == 1
    assert result["total_issues"] == 0
    assert any(s["reason"] == "ignored folder" for s in result["skipped_files"])


def test_symlink_entries_are_skipped(tmp_path):
    zip_path = tmp_path / "link.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("real.py", "x = 1\n")
        link = zipfile.ZipInfo("link.py")
        link.external_attr = (0o120777 << 16)
        zf.writestr(link, "/etc/passwd")
    result = scan_zip(str(zip_path))
    assert result["status"] == "success"
    assert result["files_scanned"] == 1
    assert any(s["reason"] == "symbolic link" for s in result["skipped_files"])


def test_windows_reserved_names_skipped(tmp_path):
    result = scan_zip(make_zip(tmp_path, {"ok.py": "x = 1\n", "con.py": "x = 2\n"}))
    assert result["files_scanned"] == 1
    assert any(s["reason"] == "reserved Windows name" for s in result["skipped_files"])


def test_oversized_file_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_zip, "MAX_PY_FILE_BYTES", 100)
    result = scan_zip(make_zip(tmp_path, {"small.py": "x = 1\n", "big.py": "x = 1\n" * 100}))
    assert result["files_scanned"] == 1
    assert any(s["name"] == "big.py" for s in result["skipped_files"])


def test_total_extracted_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_zip, "MAX_TOTAL_BYTES", 150)
    content = "x = 1\n" * 15  # 90 bytes each
    result = scan_zip(make_zip(tmp_path, {"a.py": content, "b.py": content}))
    assert result["status"] == "error"
    assert "safety limit" in result["error"].lower()


def test_too_many_python_files(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_zip, "MAX_PY_FILES", 1)
    result = scan_zip(make_zip(tmp_path, {"a.py": "x = 1\n", "b.py": "x = 2\n"}))
    assert result["status"] == "error"


def test_zip_file_too_large(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_zip, "MAX_ZIP_BYTES", 10)
    result = scan_zip(make_zip(tmp_path, {"a.py": "x = 1\n"}))
    assert result["status"] == "error"
    assert "larger" in result["error"].lower()


def test_too_many_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(safe_zip, "MAX_ARCHIVE_ENTRIES", 2)
    result = scan_zip(make_zip(tmp_path, {f"f{i}.txt": "x" for i in range(5)}))
    assert result["status"] == "error"


def test_syntax_error_file_in_zip_is_reported(tmp_path):
    result = scan_zip(make_zip(tmp_path, {"good.py": "x = 1\n", "bad.py": "def oops(:\n"}))
    assert result["status"] == "success"
    assert result["scan_errors"], "unparseable files must be reported, not silently ignored"
    assert result["warnings"]


def test_extracted_code_is_not_executed(tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"open(r'{marker}', 'w').write('x')\n"
    scan_zip(make_zip(tmp_path, {"run_me.py": code}))
    assert not marker.exists()
