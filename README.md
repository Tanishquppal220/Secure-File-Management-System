# Secure File Management System 🔐

A Streamlit-based secure file management web app with:
- Encrypted file storage (AES/Fernet)
- VirusTotal malware scanning
- User authentication with password hashing (bcrypt)
- Optional 2FA via TOTP (Google Authenticator, Authy, etc.)
- File sharing with permissions
- MongoDB for metadata and audit logs

Built in Python using **uv** (fast Python package manager), **Streamlit**, **PyMongo**, **Cryptography**, and **Requests**.

---

## Table of Contents
- [Demo](#demo)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Install uv](#install-uv)
- [Project Setup](#project-setup)
- [Configuration (Secrets)](#configuration-secrets)
- [Configure VirusTotal API](#configure-virustotal-api)
- [Run the App](#run-the-app)
- [Project Structure](#project-structure)
- [Common Issues and Fixes](#common-issues-and-fixes)
- [Security Notes](#security-notes)
- [License](#license)

---

## Demo
Run locally and open the Streamlit web UI to upload, scan, encrypt, share, and download files securely.

---

## Architecture
- **Frontend**: Streamlit multi-page app (`app.py` + `pages/`)
- **Core services**:
  - **Authentication**: bcrypt password hashing, optional TOTP 2FA
  - **File operations**: upload, AES (Fernet) encryption, download, sharing
  - **Threat detection**: VirusTotal API (hash lookup + file upload/analysis)
- **Database**: MongoDB (Atlas recommended)
- Logging: Console + rotating daily files in `logs/`

---

## Database Schema

The application uses MongoDB with the following collections and document structures:

### `users` Collection
Stores user account information and authentication details.
```json
{
  "username": "String (Unique)",
  "email": "String (Unique)",
  "password_hash": "String (Bcrypt hash)",
  "role": "String ('user' or 'admin')",
  "two_fa_enabled": "Boolean",
  "two_fa_secret": "String (Base32 TOTP secret)",
  "created_at": "DateTime",
  "last_login": "DateTime",
  "is_active": "Boolean",
  "failed_login_attempts": "Integer",
  "account_locked_until": "DateTime"
}
```

### `files` Collection
Stores metadata for uploaded files, including encryption keys and sharing permissions.
```json
{
  "file_id": "String (UUID)",
  "filename": "String",
  "owner": "String (Username)",
  "encrypted_path": "String (Path to encrypted file on disk)",
  "encryption_key": "String (Base64 encoded Fernet key)",
  "file_size": "Integer (Bytes)",
  "mime_type": "String",
  "uploaded_at": "DateTime",
  "is_shared": "Boolean",
  "shared_with": [
    {
      "username": "String",
      "permissions": ["read", "download", "write", "share"],
      "shared_at": "DateTime"
    }
  ],
  "tags": ["String"],
  "is_deleted": "Boolean (Soft delete flag)",
  "threat_scan_status": "String ('clean', 'infected', 'pending')",
  "threat_scan_result": "Object (VirusTotal scan details)"
}
```

### `access_logs` Collection
Audit trail for user actions (login, upload, download, share).
```json
{
  "timestamp": "DateTime",
  "user": "String (Username)",
  "action": "String",
  "file_id": "String (Optional)",
  "details": "String",
  "status": "String ('success', 'failed')"
}
```

### `security_logs` Collection
Logs for security-related events like malware detections or suspicious activities.
```json
{
  "timestamp": "DateTime",
  "event_type": "String",
  "threat_level": "String ('low', 'medium', 'high', 'critical')",
  "user": "String (Optional)",
  "file_id": "String (Optional)",
  "details": "String",
  "resolved": "Boolean"
}
```

---

## Prerequisites
- Python 3.12+
- A MongoDB Atlas cluster (or local MongoDB connection string)
- VirusTotal API key (free tier is sufficient)
- A TOTP Authenticator app (like Google Authenticator) for 2FA

---

## Install uv
`uv` is a fast Python package manager by Astral. Install it once, then use it to create and manage your virtual environment and dependencies.

- **macOS / Linux** (recommended):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

- **Windows** (PowerShell):
```powershell
irm https://astral.sh/uv/install.ps1 | iex
```

- **Alternative** (via pipx):
```bash
pipx install uv
```

Verify:
```bash
uv --version
```

---

## Project Setup
Clone and set up the project with `uv`.

```bash
# 1) Clone
git clone https://github.com/Tanishquppal220/Secure-File-Managment-System.git
cd Secure-File-Managment-System

# 2) Create virtual environment (Python 3.12+)
uv venv

# 3) Activate the venv
# macOS/Linux:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# 4) Install dependencies (from pyproject.toml)
uv sync
```

---

## Configuration (Secrets)
This application uses Streamlit's native secrets management.
Create a file at `.streamlit/secrets.toml` in the project root.

**Template (`.streamlit/secrets.toml`):**

```toml
[mongodb]
MONGODB_URI = "mongodb+srv://<user>:<pass>@<cluster>/?retryWrites=true&w=majority"
DATABASE_NAME = "secure_file_mgmt"

[api]
VIRUSTOTAL_API_KEY = "your_virustotal_api_key_here"

[app]
MAX_FILE_SIZE_MB = 50
ALLOWED_FILE_TYPES = "pdf,txt,docx,xlsx,jpg,png,zip"

[email]
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your.email@gmail.com"
SENDER_PASSWORD = "your_16_char_gmail_app_password"
```

**Note:**
- The `.streamlit/` directory and `secrets.toml` file are ignored by git to protect your credentials.
- Ensure you have valid MongoDB credentials and a VirusTotal API key.

---

## Configure Gmail App Password
For sending emails (e.g., 2FA codes) via Gmail SMTP:
1. Enable 2-Step Verification in your Google Account.
2. Go to [App Passwords](https://myaccount.google.com/apppasswords).
3. Create an App Password for “Mail” → “Other (Custom name)” (e.g., Secure File Mgmt).
4. Copy the 16-character password to the `SENDER_PASSWORD` field in your `secrets.toml`.

---

## Configure VirusTotal API
1. Sign up at [VirusTotal](https://www.virustotal.com/).
2. Verify your email and log in.
3. Click your profile → API key → copy it.
4. Paste it into the `VIRUSTOTAL_API_KEY` field in your `secrets.toml`.

---

## Run the App
Start the Streamlit app.

```bash
# Option A: Using the active venv python
streamlit run app.py

# Option B: Using uv
uv run streamlit run app.py
```

Open the URL shown in the terminal (typically `http://localhost:8501`).

---

## Project Structure
```
Secure-File-Managment-System/
├─ app.py               # Main entry point
├─ pages/
│  ├─ __init__.py
│  ├─ auth.py           # Login/Register/2FA views
│  ├─ dashboard.py      # Main file management view
│  ├─ upload.py         # Upload + scan + encrypt view
│  ├─ shared.py         # Shared files view
│  └─ settings.py       # User settings (Password, 2FA)
├─ src/
│  ├─ __init__.py
│  ├─ auth/
│  │  ├─ auth_manager.py     # Auth logic & user management
│  │  ├─ password_manager.py # Hashing utilities
│  │  └─ two_factor.py       # TOTP implementation
│  ├─ database/
│  │  ├─ connection.py       # MongoDB connection
│  │  └─ models.py           # Data models
│  ├─ file_ops/
│  │  └─ file_manager.py     # Encryption, Upload, Download logic
│  ├─ threat_detection/
│  │  ├─ malware_scanner.py  # Base scanner interface
│  │  └─ virustotal_scanner.py # VirusTotal integration
│  └─ utils/
│     ├─ logger.py           # Logging configuration
│     ├─ encryption.py       # AES encryption helpers
│     └─ validators.py       # Input validation
├─ .streamlit/
│  └─ secrets.toml      # Secrets configuration (gitignored)
├─ encrypted_files/     # Storage for encrypted files (gitignored)
├─ logs/                # Application logs (gitignored)
├─ pyproject.toml       # Project dependencies
├─ uv.lock              # Dependency lockfile
└── README.md
```

---

## Common Issues and Fixes

1.  **VirusTotal Connection Error**:
    *   **Cause**: Invalid API key or connection issues.
    *   **Fix**: Check `secrets.toml` for the correct `VIRUSTOTAL_API_KEY`. Ensure you have internet access.

2.  **PBKDF2 Import Error**:
    *   **Error**: `cannot import name 'PBKDF2' from ...`
    *   **Fix**: Ensure `cryptography` is up to date by running `uv sync`.

3.  **Shared Files Not Visible**:
    *   **Fix**: The system uses exact username matching. Ensure you shared it with the correct username.

4.  **MongoDB Connectivity**:
    *   **Fix**: Ensure `MONGODB_URI` in `secrets.toml` is correct and your IP address is whitelisted in your MongoDB Atlas cluster settings.

- If using SRV, your environment needs DNS that supports `_srv`.

5.  **Gmail SMTP Auth Fails**:
    *   **Fix**: Use an App Password, not your normal Gmail password. Ensure 2-Step Verification is ON in your Google Account.

---

## Security Notes
- **Git Ignore**: `.streamlit/secrets.toml`, `encrypted_files/`, and `logs/` are ignored by git to prevent sensitive data leakage.
- **Secrets**: Never commit API keys or passwords to the repository.
- **Encryption**: Files are encrypted at rest.
- **VirusTotal Limits**: The free API tier has rate limits (4 req/min, 500 req/day). The app handles this, but be aware during heavy testing.

---

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Quick Start (Copy/Paste)
```bash
git clone https://github.com/Tanishquppal220/Secure-File-Managment-System.git
cd Secure-File-Managment-System

# uv environment
uv venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
uv sync

# secrets setup
mkdir .streamlit
# Create .streamlit/secrets.toml and add:
# [mongodb]
# MONGODB_URI = "..."
# DATABASE_NAME = "secure_file_mgmt"
# [api]
# VIRUSTOTAL_API_KEY = "..."
# [app]
# MAX_FILE_SIZE_MB = 50
# ALLOWED_FILE_TYPES = "pdf,txt,docx,xlsx,jpg,png,zip"

# run
uv run streamlit run app.py
```
