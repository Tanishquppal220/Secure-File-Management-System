"""
Tests for FileManager operations, envelope encryption, rollback, and purge
"""
import io
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from cryptography.fernet import Fernet
from src.file_ops.file_manager import FileManager
from src.utils.encryption import FileEncryption
from src.threat_detection.malware_scanner import ScanStatus


@pytest.fixture
def mock_file_manager(tmp_path, monkeypatch):
    """Create a FileManager with isolated temporary directories and mock DB."""
    fm = FileManager()
    fm.upload_dir = tmp_path / "uploads"
    fm.encrypted_dir = tmp_path / "encrypted_files"
    fm.upload_dir.mkdir(exist_ok=True)
    fm.encrypted_dir.mkdir(exist_ok=True)

    # In-memory storage for mock files collection
    stored_files = {}

    def mock_insert_one(doc):
        stored_files[doc["file_id"]] = dict(doc)

    def mock_find_one(query):
        file_id = query.get("file_id")
        return stored_files.get(file_id)

    def mock_update_one(query, update):
        file_id = query.get("file_id")
        if file_id in stored_files:
            if "$set" in update:
                stored_files[file_id].update(update["$set"])

    def mock_delete_one(query):
        file_id = query.get("file_id")
        if file_id in stored_files:
            del stored_files[file_id]

    monkeypatch.setattr(fm.files_collection, "insert_one", mock_insert_one)
    monkeypatch.setattr(fm.files_collection, "find_one", mock_find_one)
    monkeypatch.setattr(fm.files_collection, "update_one", mock_update_one)
    monkeypatch.setattr(fm.files_collection, "delete_one", mock_delete_one)
    monkeypatch.setattr(fm.access_logs, "insert_one", MagicMock())
    monkeypatch.setattr(fm.security_logs, "insert_one", MagicMock())

    fm._stored_files = stored_files
    return fm


def test_upload_and_download_envelope_encryption(mock_file_manager):
    """
    Bug 1: Verify file upload wraps the per-file data key,
    and download unwraps it correctly to recover the original content.
    """
    content = b"Top secret corporate financial report"
    file_obj = io.BytesIO(content)

    success, msg, file_id = mock_file_manager.upload_file(
        file_obj, "report.pdf", "alice", scan_malware=False
    )
    assert success
    assert file_id is not None

    # Verify database document contains wrapped_key and NOT plain encryption_key
    file_doc = mock_file_manager._stored_files[file_id]
    assert "wrapped_key" in file_doc
    assert file_doc.get("encryption_key") is None or file_doc.get("encryption_key") == ""

    # Verify download succeeds and recovers identical content
    success, msg, data, filename = mock_file_manager.download_file(file_id, "alice")
    assert success
    assert data == content
    assert filename == "report.pdf"


def test_download_legacy_unwrapped_file(mock_file_manager):
    """
    Backward compatibility: Verify downloading a file from legacy database
    where raw 'encryption_key' was stored directly works seamlessly.
    """
    raw_key = FileEncryption.generate_key()
    content = b"Legacy un-enveloped document data"

    # Encrypt directly
    file_id = "legacy-123"
    enc_path = mock_file_manager.encrypted_dir / f"{file_id}.enc"
    temp_src = mock_file_manager.upload_dir / "temp_legacy.txt"
    temp_src.write_bytes(content)
    FileEncryption.encrypt_file(str(temp_src), str(enc_path), raw_key)
    temp_src.unlink()

    # Legacy document with raw encryption_key and NO wrapped_key
    mock_file_manager._stored_files[file_id] = {
        "file_id": file_id,
        "filename": "legacy.pdf",
        "owner": "alice",
        "encrypted_path": str(enc_path),
        "encryption_key": raw_key.decode("utf-8"),
        "file_size": len(content),
        "mime_type": "application/pdf",
        "is_deleted": False,
        "is_shared": False,
        "shared_with": []
    }

    success, msg, data, filename = mock_file_manager.download_file(file_id, "alice")
    assert success
    assert data == content


def test_database_insert_failure_cleans_up_encrypted_file(mock_file_manager, monkeypatch):
    """
    Bug 5a: If database insertion fails, the encrypted .enc file on disk
    MUST be rolled back (deleted) to prevent orphaned ciphertext.
    """
    content = b"Sensitive data undergoing failure test"
    file_obj = io.BytesIO(content)

    def failing_insert(doc):
        raise RuntimeError("Database connection died during insert")

    monkeypatch.setattr(mock_file_manager.files_collection, "insert_one", failing_insert)

    success, msg, file_id = mock_file_manager.upload_file(
        file_obj, "failure_test.pdf", "alice", scan_malware=False
    )
    assert not success
    assert "upload failed" in msg.lower() or "failed" in msg.lower()

    # Verify no leftover .enc files in encrypted_dir
    enc_files = list(mock_file_manager.encrypted_dir.glob("*.enc"))
    assert len(enc_files) == 0, f"Orphaned .enc files found on disk: {enc_files}"


def test_scan_status_is_derived_not_hardcoded_clean(mock_file_manager, monkeypatch):
    """
    Bug 2: Scan status written to DB must be derived from scan_result,
    never hardcoded to 'clean'.
    """
    content = b"File with custom scan result"
    file_obj = io.BytesIO(content)

    custom_scan_result = {
        "status": "safe",
        "is_safe": True,
        "threat_level": "none",
        "message": "Scan clean",
    }

    monkeypatch.setattr(
        mock_file_manager.malware_scanner,
        "scan_file",
        lambda path, force: (ScanStatus.SAFE, custom_scan_result)
    )

    success, msg, file_id = mock_file_manager.upload_file(
        file_obj, "custom_scan.pdf", "alice", scan_malware=True
    )
    assert success
    file_doc = mock_file_manager._stored_files[file_id]
    assert file_doc["threat_scan_status"] == "safe"
    assert file_doc["threat_scan_result"] == custom_scan_result


def test_scan_status_threat_or_unknown_rejects_upload(mock_file_manager, monkeypatch):
    """
    Type-system fail-closed: Any status other than ScanStatus.SAFE
    (e.g., THREAT or UNKNOWN) must abort upload and clean up temporary files.
    """
    content = b"Suspicious binary upload payload"
    file_obj = io.BytesIO(content)

    threat_result = {
        "status": "threat",
        "is_safe": False,
        "threat_level": "high",
        "message": "Trojan detected",
    }

    monkeypatch.setattr(
        mock_file_manager.malware_scanner,
        "scan_file",
        lambda path, force: (ScanStatus.THREAT, threat_result)
    )

    success, msg, file_id = mock_file_manager.upload_file(
        file_obj, "bad.pdf", "alice", scan_malware=True
    )
    assert not success
    assert "threat" in msg.lower() or "rejected" in msg.lower()
    assert file_id is None
    assert len(mock_file_manager._stored_files) == 0



def test_soft_delete_and_purge_file(mock_file_manager):
    """
    Bug 5d: Verify soft delete marks is_deleted=True,
    and purge_file physically removes the encrypted file and DB document.
    """
    content = b"Confidential file to be purged"
    file_obj = io.BytesIO(content)

    success, msg, file_id = mock_file_manager.upload_file(
        file_obj, "purge_target.pdf", "alice", scan_malware=False
    )
    assert success
    enc_path = Path(mock_file_manager._stored_files[file_id]["encrypted_path"])
    assert enc_path.exists()

    # Soft delete
    del_ok, del_msg = mock_file_manager.delete_file(file_id, "alice")
    assert del_ok
    assert mock_file_manager._stored_files[file_id]["is_deleted"] is True
    assert enc_path.exists()  # still on disk after soft delete

    # Purge
    purge_ok, purge_msg = mock_file_manager.purge_file(file_id, "alice")
    assert purge_ok
    assert not enc_path.exists()  # purged from disk
    assert file_id not in mock_file_manager._stored_files  # purged from DB
