# ThreatLens AI - Backend Service (Review 1 / Milestone 1)

Clean, modularized FastAPI backend service for **User Authentication & Role-Based Access** and **Suspicious File Upload & Static Analysis**.

---

## Repository Structure

```text
backend/
├── app/
│   ├── __init__.py
│   ├── config.py              # Path and environment configuration
│   ├── database.py            # SQLite database initialization
│   ├── main.py                # Main FastAPI app entry point
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── schemas.py         # Request/Response schemas for registration & login
│   │   └── router.py          # Auth endpoints (/api/auth/register, /login, /me)
│   └── file_upload/
│       ├── __init__.py
│       ├── analyzer.py        # Static file analysis (hashing, YARA, string indicators)
│       ├── schemas.py         # File upload response schemas
│       └── router.py          # Upload endpoints (/api/upload/scan, /scans)
├── requirements.txt           # Python dependencies
├── test_backend.py            # Automated test suite
└── README.md                  # Documentation
```

---

## Core Features (Review 1 Scope)

### 1. User Authentication & Role Management
- **Role-Based Access**: Supports roles (`Security Analyst`, `SOC Team Member`, `Administrator`, `Researcher`).
- **Endpoints**:
  - `POST /api/auth/register` — Create user account with specified security role.
  - `POST /api/auth/login` — Authenticate credentials and receive access token.
  - `GET /api/auth/me` — View current user profile information.

### 2. File Upload & Static Analysis
- **Static Workflows**:
  - File hashing (MD5, SHA-256)
  - Metadata extraction (File size, name, binary vs script type)
  - String & YARA indicator checks (detects suspicious PowerShell commands, ransomware strings, URLs)
  - Risk score calculation (0–100) and verdict (`BENIGN`, `SUSPICIOUS`, `MALWARE`)
- **Endpoints**:
  - `POST /api/upload/scan` — Upload file for static analysis and risk scoring.
  - `GET /api/upload/scans` — Retrieve scan history.

---

## Quick Start Guide

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Server**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

3. **Interactive API Documentation**:
   Open [http://localhost:8000/docs](http://localhost:8000/docs) in your browser.

4. **Run Backend Tests**:
   ```bash
   python test_backend.py
   ```
