"""
Tests for PasswordManager using bcrypt and thread offload
"""
import pytest
from src.auth.password_manager import PasswordManager


def test_hash_and_verify_password():
    """Verify password hashing generates valid bcrypt hash and verifies correctly."""
    password = "SuperSecretPassword123!"
    hashed = PasswordManager.hash_password(password)

    assert hashed is not None
    assert hashed.startswith("$2b$12$") or hashed.startswith("$2a$12$")

    # Correct password
    assert PasswordManager.verify_password(password, hashed) is True

    # Incorrect password
    assert PasswordManager.verify_password("WrongPassword123!", hashed) is False


def test_verify_invalid_hash_format():
    """Verify malformed hash format gracefully returns False without crashing."""
    assert PasswordManager.verify_password("password", "invalid_hash_string") is False
