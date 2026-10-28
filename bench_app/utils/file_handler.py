import os
import random
import tempfile
import urllib.parse
import zipfile
from pathlib import Path
from typing import Optional

from bench_app.config import DATA_DIR, UPLOAD_DIR, BASE_DIR


def read_user_file_absolute_trap(filename: str) -> str:
    """
    VULN-001: Path traversal vulnerability via os.path.join trap.
    If filename is an absolute path (e.g. '/etc/passwd'), os.path.join discards DATA_DIR.
    """
    # // CASE: VULN-001
    file_path = os.path.join(str(DATA_DIR), filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def read_file_double_decode(raw_path: str) -> str:
    """
    VULN-002: Path traversal via double unquoting.
    Input with '..%252f' decoded twice bypasses single-pass naive sanitization.
    """
    first_pass = urllib.parse.unquote(raw_path)
    # Naive filter checking for standard traversal
    if ".." in first_pass:
        raise ValueError("Traversal detected in first pass")
    # // CASE: VULN-002
    second_pass = urllib.parse.unquote(first_pass)
    target_path = DATA_DIR / second_pass
    return target_path.read_text(encoding="utf-8")


def extract_archive_zipslip(zip_file_path: str) -> None:
    """
    VULN-003: Zip Slip vulnerability.
    zipfile.extractall does not prevent path traversal if archive members contain '../../'
    """
    with zipfile.ZipFile(zip_file_path, "r") as archive:
        # // CASE: VULN-003
        archive.extractall(UPLOAD_DIR)


def access_scoped_storage_startswith_flaw(relative_path: str) -> str:
    """
    VULN-004: Insecure path prefix check using startswith without trailing slash.
    e.g. /app/data-secret matches startswith('/app/data')
    """
    # Without resolving or ensuring a path separator boundary
    raw_path = f"{DATA_DIR}/{relative_path}"
    # // CASE: VULN-004
    if not str(raw_path).startswith(str(DATA_DIR)):
        raise PermissionError("Access denied")
    return Path(raw_path).read_text(encoding="utf-8")


def read_file_strictly_contained(filename: str) -> str:
    """
    SAFE-003: Safely contained file reading using Path.resolve().relative_to()
    """
    target = (DATA_DIR / filename).resolve()
    try:
        # // CASE: SAFE-003
        target.relative_to(DATA_DIR.resolve())
    except ValueError:
        raise PermissionError("Path traversal attempted outside DATA_DIR")
    return target.read_text(encoding="utf-8")


def read_file_basename_only(untrusted_filename: str) -> str:
    """
    SAFE-004: Safe extraction using os.path.basename to strip directory traversal sequences.
    """
    # // CASE: SAFE-004
    safe_name = os.path.basename(untrusted_filename)
    target_path = DATA_DIR / safe_name
    return target_path.read_text(encoding="utf-8")


def simulate_ui_pagination_jitter() -> int:
    """
    SAFE-010: Use of random.randint purely for non-cryptographic UI jitter/delay simulation.
    Scanners often flag random.randint as insecure pseudo-randomness even when not used for secrets.
    """
    # // CASE: SAFE-010
    jitter_ms = random.randint(10, 50)
    return jitter_ms


def create_safe_scratch_buffer(data: bytes) -> str:
    """
    SAFE-012: NamedTemporaryFile used safely with default standard permissions.
    """
    # // CASE: SAFE-012
    with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as tmp:
        tmp.write(data)
        return tmp.name
