"""
Tests for malware scanner and threat detection with ScanStatus enum
"""
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from src.threat_detection.malware_scanner import ScanStatus, MalwareScanner
from src.threat_detection.virustotal_scanner import VirusTotalScanner, VirusTotalError


def test_scan_status_enum():
    """Verify ScanStatus enum defines safe, threat, and unknown."""
    assert ScanStatus.SAFE.value == "safe"
    assert ScanStatus.THREAT.value == "threat"
    assert ScanStatus.UNKNOWN.value == "unknown"


def test_scanner_fails_closed_when_api_key_missing(monkeypatch, tmp_path):
    """Bug 2a: Missing API key returns ScanStatus.UNKNOWN and is_safe=False."""
    scanner = VirusTotalScanner()
    monkeypatch.setattr(scanner, "api_key", "")

    test_file = tmp_path / "sample.pdf"
    test_file.write_bytes(b"%PDF-1.4 test content")

    scan_status, result = scanner.scan_file(str(test_file))
    assert scan_status == ScanStatus.UNKNOWN
    assert result["is_safe"] is False
    assert result["threat_level"] == "unknown"
    assert result["status"] == "unavailable"


def test_scanner_fails_closed_when_no_analysis_id(monkeypatch, tmp_path):
    """Bug 2b: Missing analysis_id returns ScanStatus.UNKNOWN and is_safe=False."""
    scanner = VirusTotalScanner()
    monkeypatch.setattr(scanner, "api_key", "valid_key")
    monkeypatch.setattr(scanner, "_get_file_report", lambda h: None)
    monkeypatch.setattr(scanner, "_upload_file", lambda f: {"data": {"id": ""}})

    test_file = tmp_path / "sample.pdf"
    test_file.write_bytes(b"%PDF-1.4 test content")

    scan_status, result = scanner.scan_file(str(test_file))
    assert scan_status == ScanStatus.UNKNOWN
    assert result["is_safe"] is False
    assert result["status"] == "pending"


def test_hash_lookup_error_handling():
    """Bug 2c: 404 is cache miss, 401/429/500 raise VirusTotalError."""
    scanner = VirusTotalScanner()
    scanner.api_key = "test_key"

    # 404 should return None (not cached)
    mock_resp_404 = MagicMock(status_code=404)
    with patch("requests.get", return_value=mock_resp_404):
        report = scanner._get_file_report("somehash")
        assert report is None

    # 401 should raise VirusTotalError
    mock_resp_401 = MagicMock(status_code=401, text="Unauthorized")
    with patch("requests.get", return_value=mock_resp_401):
        with pytest.raises(VirusTotalError):
            scanner._get_file_report("somehash")

    # 429 should raise VirusTotalError
    mock_resp_429 = MagicMock(status_code=429, text="Quota exceeded")
    with patch("requests.get", return_value=mock_resp_429):
        with pytest.raises(VirusTotalError):
            scanner._get_file_report("somehash")


def test_uncached_file_over_32mb_rejected_before_upload(tmp_path):
    """Bug 5b & 2: A >32MB file not in cache is rejected before uploading."""
    scanner = VirusTotalScanner()
    scanner.api_key = "test_key"

    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"x")

    with patch.object(scanner, "_get_file_report", return_value=None):
        with patch("pathlib.Path.stat") as mock_stat:
            mock_stat.return_value.st_size = 40 * 1024 * 1024
            scan_status, result = scanner.scan_file(str(large_file))
            assert scan_status == ScanStatus.UNKNOWN
            assert result["status"] == "unsupported"
            assert "32MB" in result["message"]


def test_large_file_cache_hit_succeeds_without_upload(tmp_path):
    """
    Bug 2 refinement: A 40MB file that IS cached in VirusTotal succeeds via
    hash-first lookup without ever hitting the 32MB upload limitation!
    """
    scanner = VirusTotalScanner()
    scanner.api_key = "test_key"

    cached_vt_report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 70,
                    "harmless": 0,
                },
                "last_analysis_date": 1700000000
            }
        }
    }

    large_file = tmp_path / "large_clean.iso"
    large_file.write_bytes(b"test data")

    with patch.object(scanner, "_get_file_report", return_value=cached_vt_report):
        with patch.object(scanner, "_upload_file") as mock_upload:
            with patch("pathlib.Path.stat") as mock_stat:
                mock_stat.return_value.st_size = 45 * 1024 * 1024
                scan_status, result = scanner.scan_file(str(large_file))

                # Hash lookup succeeded, upload was NEVER called
                mock_upload.assert_not_called()
                assert scan_status == ScanStatus.SAFE
                assert result["is_safe"] is True
                assert result["status"] == "safe"


def test_threat_detected_returns_threat_enum(tmp_path):
    """Verify malicious file report returns ScanStatus.THREAT."""
    scanner = VirusTotalScanner()
    scanner.api_key = "test_key"

    malicious_report = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 2,
                    "undetected": 50,
                    "harmless": 0,
                }
            }
        }
    }

    test_file = tmp_path / "malware.exe"
    test_file.write_bytes(b"malware content")

    with patch.object(scanner, "_get_file_report", return_value=malicious_report):
        scan_status, result = scanner.scan_file(str(test_file))
        assert scan_status == ScanStatus.THREAT
        assert result["is_safe"] is False
        assert result["status"] == "threat"
        assert result["threat_level"] == "high"
