"""
safe_zip.py - Safe extraction of Python files from an uploaded ZIP archive.

Nothing in the archive is ever executed. Only ".py" files are written to disk,
and only after passing these checks:

  * path traversal ("../", absolute paths, drive letters, backslash tricks)
    -> the WHOLE archive is rejected
  * symlinks, encrypted entries, Windows reserved names (CON, NUL, ...)
    -> that entry is skipped
  * size limits (archive size, entry count, per-file size, total extracted
    size). Sizes are enforced while streaming, not trusted from the ZIP header,
    so a "zip bomb" that lies about its size is still stopped.
"""

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# --- Limits (read at call time, so tests can change them) -------------------
MAX_ZIP_BYTES = 10 * 1024 * 1024        # size of the uploaded .zip itself
MAX_ARCHIVE_ENTRIES = 2000              # files + folders inside the archive
MAX_PY_FILES = 200                      # Python files we are willing to scan
MAX_PY_FILE_BYTES = 1 * 1024 * 1024     # size of one extracted .py file
MAX_TOTAL_BYTES = 20 * 1024 * 1024      # total extracted size

# Folders that contain third-party or generated code, not the user's own code.
SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache",
}

_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{n}" for prefix in ("COM", "LPT") for n in range(1, 10)
}


class ZipSecurityError(Exception):
    """The archive is unsafe or exceeds a limit; it must not be scanned."""


@dataclass
class ExtractionResult:
    extracted: list = field(default_factory=list)  # relative posix paths
    skipped: list = field(default_factory=list)    # {"name": ..., "reason": ...}
    total_bytes: int = 0


def _split_member_name(raw_name: str) -> list:
    """Return the path components of an archive entry, or raise if unsafe."""
    if "\x00" in raw_name:
        raise ZipSecurityError(f"Unsafe entry name (null byte): {raw_name!r}")

    name = raw_name.replace("\\", "/")  # treat Windows separators as separators

    if name.startswith("/") or (len(name) >= 2 and name[1] == ":"):
        raise ZipSecurityError(f"Unsafe absolute path in archive: {raw_name!r}")

    parts = [p for p in name.split("/") if p not in ("", ".")]

    for part in parts:
        # ".." and variants like ".. " or "..." (Windows strips trailing dots/spaces)
        if part.strip(" .") == "":
            raise ZipSecurityError(f"Unsafe path traversal in archive: {raw_name!r}")
        if ":" in part:
            raise ZipSecurityError(f"Unsafe entry name (colon): {raw_name!r}")

    return parts


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def _has_reserved_windows_name(parts: list) -> bool:
    for part in parts:
        stem = part.split(".")[0].strip().upper()
        if stem in _WINDOWS_RESERVED:
            return True
    return False


def _copy_limited(zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                  target: Path, max_bytes: int):
    """Copy one entry to disk, stopping if it exceeds max_bytes.

    Returns the number of bytes written, or None if the limit was exceeded
    (in which case the partial file is deleted).
    """
    written = 0
    exceeded = False
    with zf.open(info) as src, open(target, "wb") as dst:
        while True:
            chunk = src.read(64 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > max_bytes:
                exceeded = True
                break
            dst.write(chunk)
    if exceeded:
        target.unlink(missing_ok=True)
        return None
    return written


def extract_python_files(zip_path, dest_dir) -> ExtractionResult:
    """Safely extract only the .py files of a ZIP into dest_dir."""
    zip_path = Path(zip_path)

    if zip_path.stat().st_size > MAX_ZIP_BYTES:
        raise ZipSecurityError(
            f"ZIP file is larger than {MAX_ZIP_BYTES // (1024 * 1024)} MB."
        )

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    result = ExtractionResult()

    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()

            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise ZipSecurityError(
                    f"Archive has more than {MAX_ARCHIVE_ENTRIES} entries."
                )

            # Pass 1: validate every name before writing anything.
            members = [(info, _split_member_name(info.filename)) for info in infos]

            # Pass 2: extract eligible Python files.
            for info, parts in members:
                if info.is_dir() or not parts:
                    continue

                name = "/".join(parts)

                if _is_symlink(info):
                    result.skipped.append({"name": name, "reason": "symbolic link"})
                    continue
                if info.flag_bits & 0x1:
                    result.skipped.append({"name": name, "reason": "encrypted entry"})
                    continue
                if any(p in SKIP_DIRS for p in parts[:-1]):
                    result.skipped.append({"name": name, "reason": "ignored folder"})
                    continue
                if not parts[-1].lower().endswith(".py"):
                    result.skipped.append({"name": name, "reason": "not a Python file"})
                    continue
                if _has_reserved_windows_name(parts):
                    result.skipped.append({"name": name, "reason": "reserved Windows name"})
                    continue
                if info.file_size > MAX_PY_FILE_BYTES:
                    result.skipped.append({"name": name, "reason": "file too large"})
                    continue
                if len(result.extracted) >= MAX_PY_FILES:
                    raise ZipSecurityError(
                        f"Archive contains more than {MAX_PY_FILES} Python files."
                    )

                target = dest_resolved.joinpath(*parts).resolve()
                if not target.is_relative_to(dest_resolved):
                    raise ZipSecurityError(f"Unsafe path in archive: {info.filename!r}")

                target.parent.mkdir(parents=True, exist_ok=True)
                written = _copy_limited(zf, info, target, MAX_PY_FILE_BYTES)

                if written is None:
                    result.skipped.append({"name": name, "reason": "file too large"})
                    continue

                result.total_bytes += written
                if result.total_bytes > MAX_TOTAL_BYTES:
                    raise ZipSecurityError(
                        "Extracted size exceeds the safety limit "
                        f"({MAX_TOTAL_BYTES // (1024 * 1024)} MB)."
                    )
                result.extracted.append(name)

    except zipfile.BadZipFile:
        raise ZipSecurityError("The file is not a valid ZIP archive.")

    return result
