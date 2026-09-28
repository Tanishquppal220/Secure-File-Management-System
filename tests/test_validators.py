"""
Tests for input validation utilities
"""
import pytest
from src.utils.validators import Validators


def test_traversal_rejected():
    """Verify path traversal payloads are rejected."""
    traversal_payloads = [
        "../../etc/passwd",
        r"..\..\windows\system32",
        "..secret.txt",
        "/etc/passwd",
        r"\windows\system32",
        "sub/../../secret.txt",
        "....//test.pdf",
        ".hidden",
        "test/../test.pdf",
    ]
    for payload in traversal_payloads:
        valid, msg = Validators.validate_filename(payload)
        assert not valid, f"Payload should be rejected: {payload}"
        assert "path traversal" in msg.lower() or "invalid filename" in msg.lower()


def test_normal_filename_accepted():
    """Verify valid filenames with and without extension constraints are accepted."""
    assert Validators.validate_filename("report.pdf", ["pdf"])[0]
    assert Validators.validate_filename("document.docx", ["pdf", "docx"])[0]
    assert Validators.validate_filename("data.analysis.csv", ["csv"])[0]
    assert Validators.validate_filename("archive.zip")[0]


def test_empty_filename_rejected():
    """Verify empty filename is rejected."""
    valid, msg = Validators.validate_filename("")
    assert not valid
    assert "empty" in msg.lower()


def test_disallowed_extension_rejected():
    """Verify extensions not in allowed list are rejected."""
    valid, msg = Validators.validate_filename("malicious.exe", ["pdf", "docx"])
    assert not valid
    assert "exe" in msg.lower()
    assert "not allowed" in msg.lower()


def test_validate_file_size():
    """Verify file size limits and 0-byte file rejection."""
    # 0 bytes should be rejected
    valid, msg = Validators.validate_file_size(0, max_size_mb=32)
    assert not valid
    assert "empty" in msg.lower()

    # Valid size
    valid, msg = Validators.validate_file_size(1024 * 1024, max_size_mb=32)
    assert valid

    # Exceeding size
    valid, msg = Validators.validate_file_size(33 * 1024 * 1024, max_size_mb=32)
    assert not valid
    assert "exceeds" in msg.lower()


def test_sanitize_filename():
    """Verify filename sanitization strips dangerous characters and whitespace."""
    sanitized = Validators.sanitize_filename("folder/sub/file.pdf")
    assert "/" not in sanitized
    assert sanitized == "folder_sub_file.pdf"

    sanitized = Validators.sanitize_filename("   ...report  draft.pdf...   ")
    assert not sanitized.startswith(".")
    assert not sanitized.endswith(".")
    assert "  " not in sanitized
