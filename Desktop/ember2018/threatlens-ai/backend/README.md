# ThreatLens AI - Backend Service (Review 2 / Milestone 2)

Modular FastAPI backend service for **User Authentication & Token Management** and **Suspicious File Upload & Static Analysis**.

---

## Repository Structure

```text
backend/
├── app/
│   ├── __init__.py
│   ├── config.py              # Path and environment configuration
│   ├── database.py            # SQLite database schema & migrations
│   ├── main.py                # Main FastAPI app entry point
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── security.py        # PBKDF2 password hashing & token management
│   │   ├── schemas.py         # Request/Response validation schemas
│   │   └── router.py          # Auth endpoints & Bearer dependency
│   └── file_upload/
│       ├── __init__.py
│       ├── analyzer.py        # Static file analysis (hashes, YARA, indicators)
│       ├── schemas.py         # File upload response schemas
│       └── router.py          # Upload, lookup & scan management endpoints
├── requirements.txt           # Python dependencies
├── test_backend.py            # Automated test suite (Milestone 2)
└── README.md                  # Documentation
```

---

## Core Features (Milestone 2 Scope)

### 1. Security & User Authentication
- **PBKDF2 Password Hashing**: Passwords stored using PBKDF2-HMAC-SHA256 with 100,000 iterations and unique per-user salts.
- **HTTP Bearer Authorization**: Protected endpoints require `Authorization: Bearer <access_token>` headers.
- **Endpoints**:
  - `POST /api/auth/register` — Register account with role and hashed password.
  - `POST /api/auth/login` — Authenticate user and receive Bearer access token.
  - `GET /api/auth/me` — Protected endpoint returning logged-in profile.
  - `POST /api/auth/logout` — Revoke active access token.

### 2. File Upload & Static Analysis Backend
- **Security & Validation**: Enforces 50MB file size limit, empty file rejection, and path sanitization.
- **Static Analysis Workflows**:
  - Hashing (MD5, SHA-256)
  - String & YARA indicator analysis
  - Dynamic risk scoring (0–100) and verdict (`BENIGN`, `SUSPICIOUS`, `MALWARE`)
- **Endpoints**:
  - `POST /api/upload/scan` — Upload file for static analysis (Requires Auth).
  - `GET /api/upload/scans` — Retrieve overall scan history (Requires Auth).
  - `GET /api/upload/scans/{scan_id}` — Retrieve details of a specific scan ID (Requires Auth).
  - `DELETE /api/upload/scans/{scan_id}` — Delete scan record by ID (Requires Auth).

---

## 4-Milestone Roadmap Summary

1. **Milestone 1**: Initial routing setup, SQLite database schema, basic unauthenticated scan endpoint.
2. **Milestone 2 (Completed)**: PBKDF2 password hashing, Bearer token authorization middleware, upload limits & sanitization, scan retrieval by ID, and scan record deletion.
3. **Milestone 3 (Next)**: Asynchronous EMBER LightGBM deep feature extraction pipeline and refresh token rotation.
4. **Milestone 4**: Sandbox dynamic analysis triggers, RBAC permission matrix enforcement, and audit logs.

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

4. **Run Milestone 2 Automated Test Suite**:
   ```bash
   python test_backend.py
   ```
