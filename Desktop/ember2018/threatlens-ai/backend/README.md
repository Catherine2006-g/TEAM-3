# ThreatLens AI - Backend Service (Authentication & File Upload Backend)

Production-grade modular FastAPI backend service providing **User Authentication & PBKDF2 Password Security**, **Token Rotation**, **Suspicious File Upload & Static/Dynamic Analysis**, **RBAC Governance**, and **Security Audit Logging**.

---

## Repository Structure

```text
backend/
├── app/
│   ├── __init__.py
│   ├── config.py              # Directory paths & environment setup
│   ├── database.py            # SQLite database schema, tables & auto-migrations
│   ├── main.py                # Main FastAPI application entry point
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── security.py        # PBKDF2 hashing, salt generation & token rotation
│   │   ├── schemas.py         # Auth Pydantic request & response validation schemas
│   │   └── router.py          # User register, login, refresh, profile & logout endpoints
│   ├── file_upload/
│   │   ├── __init__.py
│   │   ├── analyzer.py        # Hashing, YARA, string indicators, EMBER ML & sandbox
│   │   ├── schemas.py         # File scan Pydantic schemas
│   │   └── router.py          # Upload, async pipeline, sandbox & scan management endpoints
│   └── audit/
│       ├── __init__.py
│       ├── service.py         # Persistent security audit logging service
│       ├── schemas.py         # Audit log response schemas
│       └── router.py          # Admin audit log inspection endpoint
├── requirements.txt           # Python dependencies
├── test_backend.py            # Automated test suite (Milestones 1-4 & Edge Cases)
└── README.md                  # Comprehensive Integration Documentation
```

---

## Core Capabilities & Completed Milestones

### 1. User Authentication & Role Management
- **PBKDF2 Password Hashing**: Password security stored using PBKDF2-HMAC-SHA256 with 100,000 iterations and per-user random 16-byte salts.
- **HTTP Bearer Authorization**: Protected endpoints require `Authorization: Bearer <access_token>` headers.
- **Refresh Token Rotation**: Endpoint `/api/auth/refresh` rotates refresh tokens and enforces replay protection.
- **Session Revocation**: Logout immediately revokes active Bearer tokens.

### 2. File Upload & Analysis Engine
- **Input Sanitization & Limits**: 50MB maximum file size limit, 0-byte file rejection, and path traversal prevention.
- **Static Analysis Workflows**: MD5 & SHA-256 calculation, string indicators, YARA rules, and EMBER LightGBM ML model detection.
- **Asynchronous Background Processing**: Endpoint `POST /api/upload/scan/async` returns immediately while background workers process extraction.
- **Sandbox Dynamic Behavioral Analysis**: Endpoint `POST /api/upload/scans/{scan_id}/sandbox` simulates dynamic malware behaviors.

### 3. Role-Based Access Control (RBAC) Matrix

| Endpoint | Method | Allowed Roles |
| :--- | :--- | :--- |
| `/api/auth/register` | `POST` | Public |
| `/api/auth/login` | `POST` | Public |
| `/api/auth/refresh` | `POST` | Public |
| `/api/auth/me` | `GET` | Authenticated Users |
| `/api/auth/logout` | `POST` | Authenticated Users |
| `/api/upload/scan` | `POST` | Administrator, Security Analyst, Researcher |
| `/api/upload/scan/async` | `POST` | Administrator, Security Analyst, Researcher |
| `/api/upload/scans/{scan_id}/sandbox` | `POST` | Administrator, Security Analyst, Researcher |
| `/api/upload/scans` | `GET` | Authenticated Users |
| `/api/upload/scans/{scan_id}` | `GET` | Authenticated Users |
| `/api/upload/scans/{scan_id}` | `DELETE` | **Administrator ONLY** |
| `/api/audit/logs` | `GET` | **Administrator ONLY** |

---

## Teammate Integration Guide & API Specifications

### 1. Register Account
`POST /api/auth/register`
```json
// Request Body
{
  "username": "analyst_john",
  "email": "john@threatlens.ai",
  "password": "SecurePassword123!",
  "role": "Security Analyst",
  "full_name": "John Doe"
}
```

### 2. Login & Receive Tokens
`POST /api/auth/login`
```json
// Request Body
{
  "username": "analyst_john",
  "password": "SecurePassword123!"
}

// Response (200 OK)
{
  "status": "success",
  "access_token": "tl_sec_...",
  "refresh_token": "tl_ref_...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "analyst_john",
    "email": "john@threatlens.ai",
    "role": "Security Analyst",
    "full_name": "John Doe"
  }
}
```

### 3. Upload File for Static Analysis
`POST /api/upload/scan`
- **Header**: `Authorization: Bearer <access_token>`
- **Body**: `multipart/form-data` with form field `file`.

```json
// Response (200 OK)
{
  "scan_id": "SCAN-5E768F",
  "filename": "suspicious.exe",
  "file_size": 1024,
  "file_type": "Windows Executable (.exe)",
  "hashes": {
    "md5": "e110...",
    "sha256": "4b5d..."
  },
  "static_analysis": {
    "yara_matches": ["Ransomware_Behavior"],
    "suspicious_indicators": ["Command shell execution string found"],
    "is_executable": true,
    "ml_engine": {
      "malware_probability": 94.2,
      "prediction": "MALWARE"
    }
  },
  "detection": {
    "risk_score": 85,
    "verdict": "MALWARE",
    "recommended_action": "Quarantine File"
  },
  "uploaded_by": "analyst_john",
  "timestamp": "2026-09-10 16:43:00"
}
```

### 4. JavaScript / Frontend Integration Snippet
```javascript
// Example: File Upload using fetch API
async function uploadSuspiciousFile(fileInput, accessToken) {
  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  const response = await fetch('http://localhost:8000/api/upload/scan', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`
    },
    body: formData
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Upload failed');
  }

  const scanResult = await response.json();
  console.log('Scan Verdict:', scanResult.detection.verdict);
  return scanResult;
}
```

---

## Quick Start & Verification

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Launch API Server**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

3. **Interactive Swagger Documentation**:
   Open [http://localhost:8000/docs](http://localhost:8000/docs) in your browser.

4. **Run Comprehensive Test Suite**:
   ```bash
   python test_backend.py
   ```
