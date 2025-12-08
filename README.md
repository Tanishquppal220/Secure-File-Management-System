# Secure File Management System 🔐

A Streamlit-based secure file management web app with:
- Encrypted file storage (AES/Fernet)
- VirusTotal malware scanning
- User authentication with password hashing (bcrypt)
- Optional 2FA via TOTP (Google Authenticator)
- File sharing with permissions
- MongoDB for metadata and audit logs

Built in Python using uv (fast Python package manager), Streamlit, PyMongo, Cryptography, and Requests.

---

## Table of Contents
- [Demo](#demo)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Install uv](#install-uv)
- [Project Setup](#project-setup)
- [Environment Variables](#environment-variables)
- [Generate Security Keys](#generate-security-keys)
- [Configure Gmail App Password](#configure-gmail-app-password)
- [Configure VirusTotal API](#configure-virustotal-api)
- [Run the App](#run-the-app)
- [Run Validation Tests](#run-validation-tests)
- [Project Structure](#project-structure)
- [Common Issues and Fixes](#common-issues-and-fixes)
- [Security Notes](#security-notes)
- [License](#license)

---

## Demo
Run locally and open the Streamlit web UI to upload, scan, encrypt, share, and download files securely.

---

## Architecture
- Frontend: Streamlit multi-page app (app.py + pages/)
- Core services:
  - Authentication: bcrypt password hashing, optional TOTP 2FA
  - File operations: upload, AES (Fernet) encryption, download, sharing
  - Threat detection: VirusTotal API (hash lookup + file upload/analysis)
- Database: MongoDB (Atlas recommended)
- Logging: Console + rotating daily files in logs/

---

## Prerequisites
- Python 3.12+
- A MongoDB Atlas cluster (or MongoDB connection string)
- Gmail account (for 2FA email, if used) with an App Password
- VirusTotal API key (free tier is fine)

---

## Install uv
uv is a fast Python package manager by Astral. Install it once, then use it to create and manage your virtual environment and dependencies.

- macOS / Linux (recommended):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

- Windows (PowerShell):
```powershell
irm https://astral.sh/uv/install.ps1 | iex
```

- Alternative (via pipx):
```bash
pipx install uv
```

Verify:
```bash
uv --version
```

---

## Project Setup
Clone and set up the project with uv.

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

# 4) Install dependencies (from pyproject.toml / uv.lock)
uv sync
```

Note: You can also run commands through uv directly:
- `uv run streamlit run app.py` (runs within the env)
- `uv run python test_part1.py` (etc.)

---

## Environment Variables
Create a `.env` file in the project root. Use this template:

```ini
# MongoDB
MONGODB_URI=mongodb+srv://<user>:<pass>@<cluster>/?retryWrites=true&w=majority
DATABASE_NAME=secure_file_mgmt

# Security keys (see next section to generate)
SECRET_KEY=your_generated_secret_key_here
ENCRYPTION_KEY=your_generated_encryption_key_here

# Email (Gmail SMTP) for 2FA/email notifications
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your.email@gmail.com
SENDER_PASSWORD=your_16_char_gmail_app_password

# Malware scanning (VirusTotal)
VIRUSTOTAL_API_KEY=your_64_char_virustotal_api_key

# App config
MAX_FILE_SIZE_MB=50
ALLOWED_FILE_TYPES=pdf,txt,docx,xlsx,jpg,png,zip
SESSION_TIMEOUT_MINUTES=30
```

Important:
- Do NOT add spaces around the equals sign, e.g. use `KEY=value` not `KEY = value`.
- `.env` is ignored by git (see .gitignore).

---

## Generate Security Keys
A helper script is included to generate strong keys.

```bash
uv run python secure_key_gen.py
```

Copy the printed `SECRET_KEY` and `ENCRYPTION_KEY` into your `.env`.

---

## Configure Gmail App Password
For sending emails (e.g., 2FA codes) via Gmail SMTP:
1. Enable 2-Step Verification in your Google Account.
2. Go to App Passwords: https://myaccount.google.com/apppasswords
3. Create an App Password for “Mail” → “Other (Custom name)” (e.g., Secure File Mgmt)
4. Copy the 16-character password to `.env` as `SENDER_PASSWORD`.

---

## Configure VirusTotal API
1. Sign up at https://www.virustotal.com/
2. Verify your email and log in.
3. Click your profile → API key → copy it.
4. Add to `.env` as `VIRUSTOTAL_API_KEY` (no spaces before/after the key).

---

## Run the App
Start the Streamlit app.

```bash
# Option A: Using the active venv python
streamlit run app.py

# Option B: Using uv
uv run streamlit run app.py
```

Open the URL shown in the terminal (typically http://localhost:8501).

---

## Run Validation Tests
Quick checks to confirm each part works (run any/all that are present):

```bash
uv run python test_part1.py   # Utils, DB models, Auth primitives
uv run python test_part2.py   # Malware scanner + file ops wiring
uv run python test_part3.py   # Streamlit files/pages presence
uv run python test_db.py      # Mongo connectivity check (if configured)
uv run python test_smtp.py    # Gmail SMTP (using your app password)
uv run python test_virustotal_fix.py  # VirusTotal path + connectivity
```

---

## Project Structure
```
Secure-File-Managment-System/
├─ app.py
├─ pages/
│  ├─ __init__.py
│  ├─ auth.py           # Login/Register/2FA
│  ├─ dashboard.py      # My Files page
│  ├─ upload.py         # Upload + scan + encrypt
│  └─ shared.py         # Files shared with me
│  └─ settings.py       # Change password, enable/disable 2FA, logs
├─ src/
│  ├─ __init__.py
│  ├─ auth/
│  │  ├─ __init__.py
│  │  ├─ auth_manager.py
│  │  ├─ password_manager.py
│  │  └─ two_factor.py
│  ├─ database/
│  │  ├─ __init__.py
│  │  ├─ connection.py
│  │  └─ models.py
│  ├─ file_ops/
│  │  ├─ __init__.py
│  │  └─ file_manager.py
│  ├─ threat_detection/
│  │  ├─ __init__.py
│  │  ├─ malware_scanner.py
│  │  └─ virustotal_scanner.py
│  └─ utils/
│     ├─ __init__.py
│     ├─ logger.py
│     ├─ encryption.py
│     └─ validators.py
├─ uploads/           # ignored (kept with .gitkeep)
├─ encrypted_files/   # ignored (kept with .gitkeep)
├─ logs/              # ignored (kept with .gitkeep)
├─ .env               # ignored (your secrets live here)
├─ pyproject.toml     # dependencies (used by uv)
├─ uv.lock            # lockfile (for reproducible installs)
├─ requirements.txt   # optional mirror (if present)
├─ secure_key_gen.py
└─ README.md
```

---

## Common Issues and Fixes

1) VirusTotal host looks like `www.%20virustotal.com`  
Cause: extra whitespace somewhere in base URL or API key env.  
Fix:
- Ensure `.env` has no spaces around `=` and no trailing spaces in `VIRUSTOTAL_API_KEY`.
- The code strips whitespace in the VirusTotal scanner, but still keep `.env` clean.

2) PBKDF2 import error  
Error: `cannot import name 'PBKDF2' from ...kdf.pbkdf2`  
Fix: We use `PBKDF2HMAC` (current cryptography API). Ensure cryptography is up to date:  
```bash
uv sync  # or uv add cryptography --upgrade
```

3) Streamlit triggers 2FA setup twice  
Cause: Streamlit reruns the script on interactions.  
Fix: The settings page uses session-state flags (`setting_up_2fa`, etc.) to call the setup only once.

4) Shared files not visible for the other user  
Fix: Query uses `$elemMatch` on `shared_with` to correctly retrieve shared items.

5) MongoDB connectivity  
- Ensure `MONGODB_URI` is correct and your IP/network is allowed in Atlas.
- If using SRV, your environment needs DNS that supports `_srv`.

6) Gmail SMTP auth fails  
- Use App Password, not your normal Gmail password.
- Ensure 2-Step Verification is ON in Google Account.

---

## Security Notes
- `.env`, `uploads/`, `encrypted_files/`, and `logs/` are ignored by git.
- Never commit secrets (API keys, passwords) to the repository.
- VirusTotal free tier has rate limits (4 req/min, 500 req/day); handle failures gracefully.
- All uploaded files are encrypted on disk; keys are stored per-file in DB metadata (Fernet key as base64). Protect your DB!

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

# env
cp .env.example .env        # if present, else create .env using the template above
uv run python secure_key_gen.py
# paste SECRET_KEY and ENCRYPTION_KEY into .env
# add MONGODB_URI, Gmail App password, VIRUSTOTAL_API_KEY to .env (no spaces)

# run
uv run streamlit run app.py
```

Happy building! 🚀