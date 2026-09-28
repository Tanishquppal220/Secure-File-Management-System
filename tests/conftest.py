"""
Pytest configuration and shared fixtures
"""
import os
import pytest
from cryptography.fernet import Fernet
import streamlit as st


@pytest.fixture(autouse=True)
def setup_test_secrets(monkeypatch):
    """Ensure streamlit secrets has required keys for testing."""
    test_master_key = Fernet.generate_key().decode()
    secrets_dict = {
        "mongodb": {
            "MONGODB_URI": "mongodb://localhost:27017",
            "DATABASE_NAME": "test_secure_file_mgmt"
        },
        "api": {
            "VIRUSTOTAL_API_KEY": "test_vt_api_key_12345"
        },
        "app": {
            "MAX_FILE_SIZE_MB": 32,
            "ALLOWED_FILE_TYPES": "pdf,txt,docx,xlsx,jpg,png,zip",
            "MASTER_ENCRYPTION_KEY": test_master_key
        },
        "email": {
            "SMTP_SERVER": "smtp.gmail.com",
            "SMTP_PORT": 587,
            "SENDER_EMAIL": "test@example.com",
            "SENDER_PASSWORD": "test_password"
        }
    }

    # Monkeypatch st.secrets
    monkeypatch.setattr(st, "secrets", secrets_dict)
    return secrets_dict
