"""
Tests for Two-Factor Authentication and 2FA brute-force protection
"""
from datetime import datetime, timedelta, timezone
import pytest
import pyotp
from unittest.mock import MagicMock
from src.auth.two_factor import TwoFactorAuth
from src.auth.auth_manager import AuthManager


def test_totp_generation_and_verification():
    """Verify TOTP secret generation, URI, and verification."""
    two_fa = TwoFactorAuth()
    secret = two_fa.generate_secret()
    assert len(secret) == 32

    uri = two_fa.get_totp_uri("alice", secret)
    assert "alice" in uri
    assert secret in uri

    totp = pyotp.TOTP(secret)
    token = totp.now()

    assert two_fa.verify_totp(secret, token)
    assert not two_fa.verify_totp(secret, "000000")


def test_2fa_lockout_after_repeated_invalid_codes(monkeypatch):
    """
    Verify 5 consecutive failed 2FA attempts lock the user account,
    and subsequent attempts are blocked immediately.
    """
    auth = AuthManager()

    # Create mock user in database
    mock_user = {
        "username": "bob",
        "email": "bob@example.com",
        "two_fa_enabled": True,
        "two_fa_secret": pyotp.random_base32(),
        "failed_2fa_attempts": 0,
        "account_locked_until": None,
        "is_active": True,
    }

    def mock_find_one(query):
        if query.get("username") == "bob":
            return mock_user
        return None

    def mock_update_one(query, update):
        if query.get("username") == "bob":
            set_vals = update.get("$set", {})
            mock_user.update(set_vals)

    monkeypatch.setattr(auth.users_collection, "find_one", mock_find_one)
    monkeypatch.setattr(auth.users_collection, "update_one", mock_update_one)
    monkeypatch.setattr(auth.access_logs, "insert_one", MagicMock())

    # 4 invalid attempts should increment counter but NOT lock yet
    for attempt in range(1, 5):
        success, msg, data = auth.verify_2fa_and_login("bob", "999999")
        assert not success
        assert "Invalid 2FA code" in msg
        assert mock_user["failed_2fa_attempts"] == attempt
        assert mock_user["account_locked_until"] is None

    # 5th invalid attempt MUST trigger account lockout
    success, msg, data = auth.verify_2fa_and_login("bob", "999999")
    assert not success
    assert "locked" in msg.lower()
    assert mock_user["failed_2fa_attempts"] >= 5
    assert mock_user["account_locked_until"] is not None
    assert mock_user["account_locked_until"] > datetime.now(timezone.utc)

    # 6th attempt should be blocked at the gate due to account lockout
    success, msg, data = auth.verify_2fa_and_login("bob", "123456")
    assert not success
    assert "locked" in msg.lower()


def test_2fa_success_resets_failed_counter(monkeypatch):
    """Verify successful 2FA resets failed attempts and clears lockout."""
    auth = AuthManager()
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    mock_user = {
        "username": "charlie",
        "email": "charlie@example.com",
        "two_fa_enabled": True,
        "two_fa_secret": secret,
        "failed_2fa_attempts": 3,
        "account_locked_until": None,
        "is_active": True,
    }

    monkeypatch.setattr(auth.users_collection, "find_one", lambda q: mock_user)
    monkeypatch.setattr(auth.users_collection, "update_one", lambda q, u: mock_user.update(u.get("$set", {})))
    monkeypatch.setattr(auth.access_logs, "insert_one", MagicMock())

    success, msg, data = auth.verify_2fa_and_login("charlie", valid_code)
    assert success
    assert "successful" in msg.lower()
    assert mock_user["failed_2fa_attempts"] == 0
    assert mock_user.get("account_locked_until") is None
