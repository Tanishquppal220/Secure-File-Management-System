<p align="center">
  <img src="./assets/readme/hero.svg" width="100%" alt="Secure File Management System — Encrypt, scan, share, and audit files end-to-end in a Streamlit web app.">
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.12%2B-00c2a8?style=flat-square&logo=python&logoColor=white&labelColor=0d1220" alt="Python 3.12+"></a>
  <a href="https://streamlit.io"><img src="https://img.shields.io/badge/Streamlit-1.51%2B-00c2a8?style=flat-square&logo=streamlit&logoColor=white&labelColor=0d1220" alt="Streamlit"></a>
  <a href="https://www.mongodb.com/atlas"><img src="https://img.shields.io/badge/MongoDB-Atlas-00c2a8?style=flat-square&logo=mongodb&logoColor=white&labelColor=0d1220" alt="MongoDB"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00c2a8?style=flat-square&labelColor=0d1220" alt="MIT License"></a>
</p>

---

Upload a file. It gets scanned for malware by 70+ antivirus engines, encrypted at rest with Fernet (a per-file key for every file), and stored. Share it with teammates using granular permissions. Every action is logged. All of this runs in a browser with a single command.

---

## Quick Start

**Prerequisites:** Python 3.12+, MongoDB URI, VirusTotal API key.

```bash
# 1. Clone and enter the project
git clone https://github.com/Tanishquppal220/Secure-File-Managment-System.git
cd Secure-File-Managment-System

# 2. Set up the environment with uv
uv venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
uv sync

# 3. Create secrets file from template
cp .streamlit/secrets.example.toml .streamlit/secrets.toml

# Generate a 32-byte Fernet master key:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Paste the generated key into MASTER_ENCRYPTION_KEY inside .streamlit/secrets.toml,
# and fill in your MONGODB_URI and VIRUSTOTAL_API_KEY.

# 4. Run
uv run streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

## How It Works

Every file passes through four security layers in sequence:

| Layer | Mechanism | Implementation |
|---|---|---|
| **Identity** | TOTP two-factor authentication | `pyotp`, bcrypt password hashing |
| **Encryption** | Fernet at rest (AES-128-CBC + HMAC-SHA256), per-file keys | `cryptography` library |
| **Threat detection** | VirusTotal hash lookup + file scan | 70+ AV engines via REST API |
| **Audit** | Immutable access and security event logs | MongoDB `access_logs` + `security_logs` |

File sharing uses explicit per-user permissions (`read`, `download`, `write`, `share`). Accounts lock after repeated failed logins.

---

## Prerequisites

| Requirement | Where to get it |
|---|---|
| Python 3.12+ | [python.org](https://www.python.org/downloads/) |
| `uv` package manager | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| MongoDB Atlas URI | [mongodb.com/atlas](https://www.mongodb.com/atlas) (free tier works) |
| VirusTotal API key | [virustotal.com](https://www.virustotal.com/) → profile → API key |
| Gmail App Password | Google Account → Security → App Passwords (16-char) |

---

## Configuration Reference

All secrets live in `.streamlit/secrets.toml` (gitignored — never committed).

```toml
[mongodb]
MONGODB_URI      = "mongodb+srv://..."   # Atlas connection string
DATABASE_NAME    = "secure_file_mgmt"

[api]
VIRUSTOTAL_API_KEY = "..."               # Free tier: 4 req/min, 500 req/day

[app]
MAX_FILE_SIZE_MB   = 50
ALLOWED_FILE_TYPES = "pdf,txt,docx,xlsx,jpg,png,zip"

[email]
SMTP_SERVER     = "smtp.gmail.com"
SMTP_PORT       = 587
SENDER_EMAIL    = "..."                  # Gmail address
SENDER_PASSWORD = "..."                  # 16-char App Password (not your login password)
```

### Getting a Gmail App Password

1. Enable **2-Step Verification** in your Google Account.
2. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
3. Create a password for **Mail → Other** (e.g., "Secure File Mgmt").
4. Copy the 16-character result into `SENDER_PASSWORD`.

---

## Project Structure

```
Secure-File-Managment-System/
├── app.py                    # Streamlit entry point
├── pages/
│   ├── auth.py               # Login, register, 2FA setup
│   ├── dashboard.py          # File management view
│   ├── upload.py             # Upload → scan → encrypt flow
│   ├── shared.py             # Files shared with you
│   └── settings.py           # Password and 2FA settings
├── src/
│   ├── auth/
│   │   ├── auth_manager.py   # Auth logic, account locking
│   │   ├── password_manager.py  # bcrypt hashing
│   │   └── two_factor.py     # TOTP (pyotp)
│   ├── database/
│   │   ├── connection.py     # MongoDB connection pool
│   │   └── models.py         # Document schemas
│   ├── file_ops/
│   │   └── file_manager.py   # Encrypt, upload, download, share
│   ├── threat_detection/
│   │   ├── malware_scanner.py      # Base scanner interface
│   │   └── virustotal_scanner.py   # VirusTotal REST integration
│   └── utils/
│       ├── encryption.py     # AES helpers
│       ├── logger.py         # Rotating daily logs
│       └── validators.py     # Input validation
├── .streamlit/secrets.toml   # Secrets (gitignored)
├── encrypted_files/          # Encrypted storage (gitignored)
├── logs/                     # Application logs (gitignored)
└── pyproject.toml            # Dependencies (managed with uv)
```

---

## Database Schema

<details>
<summary><strong>users</strong> — account info and auth state</summary>

```json
{
  "username":              "String (unique)",
  "email":                 "String (unique)",
  "password_hash":         "String (bcrypt)",
  "role":                  "'user' | 'admin'",
  "two_fa_enabled":        "Boolean",
  "two_fa_secret":         "String (Base32 TOTP secret)",
  "created_at":            "DateTime",
  "last_login":            "DateTime",
  "is_active":             "Boolean",
  "failed_login_attempts": "Integer",
  "account_locked_until":  "DateTime"
}
```
</details>

<details>
<summary><strong>files</strong> — metadata, encryption keys, sharing permissions</summary>

```json
{
  "file_id":           "String (UUID)",
  "filename":          "String",
  "owner":             "String (username)",
  "encrypted_path":    "String",
  "wrapped_key":       "String (Fernet-wrapped Base64 data key)",
  "file_size":         "Integer (bytes)",
  "mime_type":         "String",
  "uploaded_at":       "DateTime",
  "is_shared":         "Boolean",
  "shared_with":       [{ "username": "String", "permissions": ["read","download","write","share"], "shared_at": "DateTime" }],
  "tags":              ["String"],
  "is_deleted":        "Boolean",
  "threat_scan_status":"'safe' | 'threat' | 'unknown' | 'pending'",
  "threat_scan_result":"Object (VirusTotal response)"
}
```
</details>

<details>
<summary><strong>access_logs</strong> and <strong>security_logs</strong> — full audit trail</summary>

```json
// access_logs — every login, upload, download, share
{
  "timestamp": "DateTime",
  "user":      "String",
  "action":    "String",
  "file_id":   "String (optional)",
  "details":   "String",
  "status":    "'success' | 'failed'"
}

// security_logs — malware detections and suspicious events
{
  "timestamp":    "DateTime",
  "event_type":   "String",
  "threat_level": "'low' | 'medium' | 'high' | 'critical'",
  "user":         "String (optional)",
  "file_id":      "String (optional)",
  "details":      "String",
  "resolved":     "Boolean"
}
```
</details>

---

## Troubleshooting

| Issue | Fix |
|---|---|
| **VirusTotal connection error** | Check `VIRUSTOTAL_API_KEY` in `secrets.toml`. Confirm internet access. |
| **Missing `MASTER_ENCRYPTION_KEY`** | Add `MASTER_ENCRYPTION_KEY` to `.streamlit/secrets.toml` using `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. |
| **`cannot import name 'PBKDF2'`** | Run `uv sync` to update `cryptography`. |
| **Shared file not visible** | Sharing uses exact username matching. Confirm the correct username was used. |
| **MongoDB connection fails** | Verify `MONGODB_URI` and whitelist your IP in Atlas → Network Access. |
| **Gmail SMTP auth fails** | Use a 16-char App Password, not your account password. 2-Step Verification must be ON. |

---

## Security Notes

- **Secrets** — `.streamlit/secrets.toml`, `encrypted_files/`, and `logs/` are gitignored. Never commit API keys.
- **Encryption** — files are encrypted at rest with a per-file Fernet key (AES-128-CBC + HMAC-SHA256). Corrupt ciphertext, a wrong key, and a single flipped byte all raise a clean typed `InvalidToken` rather than leaking a raw exception.
- **Authorization** — permissions are checked inside `download_file` on every read, not at share time, so revoking a share takes effect immediately.
- **Secret hygiene** — no hardcoded credentials in source; all secrets load from `st.secrets`.
- **Rate limits** — VirusTotal free tier: 4 requests/min, 500 requests/day. The scanner is hash-first, so re-uploading an identical file consumes no quota. Cold scans poll at 15-second intervals with exponential/quota backoff to respect the 4/min limit.
- **Account protection** — accounts lock for 15 minutes after 5 failed password attempts or 5 failed 2FA TOTP attempts.

### Key Custody & KMS Architecture Trade-Offs

- **The Custody Trade-Off**: Moving from collocated plaintext keys to envelope encryption trades *"an attacker who compromises the database compromises every file"* for *"an operator who loses the master key permanently loses access to all data"*. Because ciphertext is wrapped with the per-file data key and the data key is wrapped by `MASTER_ENCRYPTION_KEY`, losing `.streamlit/secrets.toml` without a backup is unrecoverable.
- **Production Migration Path**: In production deployments, `MASTER_ENCRYPTION_KEY` should not reside in a static configuration file on disk. Instead, key wrapping and unwrapping operations should be delegated to a Hardware Security Module (HSM) or managed Key Management Service (KMS) such as **AWS KMS**, **Google Cloud KMS**, or **HashiCorp Vault Transit Engine** (e.g., using `kms:Encrypt` and `kms:Decrypt` with IAM role-based access control, automated key rotation, and strict audit logging).

### Security Controls & Architecture Status

| Architecture / Security Control | Description | Status |
| --- | --- | --- |
| **Envelope Encryption (per-file data key + master key)** | Per-file Fernet data keys are encrypted (wrapped) by a master key stored outside the database (`MASTER_ENCRYPTION_KEY` in secrets / KMS). Old records remain readable via backward-compatible unwrap. | **Resolved** |
| **Fail-Closed Tri-State Malware Scanner** | Replaced boolean scanner with explicit `ScanStatus` tri-state (`safe`, `threat`, `unknown`). Missing API keys, missing analysis IDs, and lookup errors fail closed. Dynamic derivation eliminates false clean attestations. | **Resolved** |
| **Path Traversal Guard** | Replaced `'. .'` no-op with robust traversal checks (`..`, separators, null bytes, leading dots) and safe path resolution. | **Resolved** |
| **2FA TOTP Rate Limiting & Account Lockout** | 5 consecutive invalid TOTP attempts trigger a 15-minute account lockout, with constant-time delay on failure to thwart timing attacks. | **Resolved** |
| **Orphaned Ciphertext Prevention** | Database insertions are wrapped in an atomic rollback block that deletes `.enc` files from disk if MongoDB fails. | **Resolved** |
| **File Size Alignment with VirusTotal** | Uploads are aligned to 32 MB and guarded before initiating API calls. SHA-256 cache hits are checked first for zero-quota lookups on files of any allowed size. | **Resolved** |
| **VirusTotal Poll Cadence & Backoff** | Polling backoff increased to 15-second intervals with 429 rate limit detection. | **Resolved** |
| **Data Erasure & Purge Path** | Hard purge method (`purge_file` and `purge_deleted_files`) added to permanently wipe ciphertext and metadata. | **Resolved** |
| **bcrypt Concurrency Offloading** | Password hashing/verification (rounds=12) is offloaded to a bounded worker thread pool to release the GIL without blocking. | **Resolved** |
| **Automated Test Suite** | 30 automated unit/integration tests with 59% code coverage across `src/`. | **Resolved** |
| **Untested Concurrency** | `DatabaseConnection.__new__` is not thread-safe, and uploads are not concurrency-tested. | Open — acceptable for local demo |

---

## License

MIT — see [LICENSE](LICENSE) for details.
