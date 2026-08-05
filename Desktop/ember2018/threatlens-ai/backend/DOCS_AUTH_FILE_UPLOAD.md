# ThreatLens AI - Basic Authentication & File Upload (Part 2/10)

## Overview
This document provides beginner-friendly ("naive developer") documentation for the first 2 basic modules of ThreatLens AI:
1. **User Authentication & Role-Based Access Control Module**
2. **File Upload & Basic Static Analysis Module**

---

## 1. Authentication Module

The authentication module manages platform users and their security roles.

### User Roles
- **Security Analyst**: Uploads suspicious files, runs static scans, views reports.
- **SOC Team Member**: Monitors detection logs, tracks malware incidents.
- **Administrator**: Manages platform settings and user roles.
- **Researcher**: Uploads malware samples and analyzes malware families.

### API Endpoints

#### Register User
`POST /api/register`

Example Request Body:
```json
{
  "username": "analyst_jane",
  "email": "jane@threatlens.ai",
  "password": "Password123!",
  "role": "Security Analyst",
  "full_name": "Jane Doe"
}
```

Example Response:
```json
{
  "status": "success",
  "message": "User 'analyst_jane' registered successfully",
  "user": {
    "username": "analyst_jane",
    "email": "jane@threatlens.ai",
    "role": "Security Analyst"
  }
}
```

#### Login User
`POST /api/login`

Example Request Body:
```json
{
  "username": "analyst_jane",
  "password": "Password123!"
}
```

Example Response:
```json
{
  "status": "success",
  "access_token": "token_analyst_jane_a1b2c3d4",
  "user": {
    "username": "analyst_jane",
    "email": "jane@threatlens.ai",
    "role": "Security Analyst",
    "full_name": "Jane Doe"
  }
}
```

---

## 2. File Upload & Static Analysis Module

The file upload module handles suspicious file uploads and performs initial static analysis.

### Analysis Workflow
1. **File Upload**: Accepts multipart file upload and saves to `/uploads/`.
2. **Cryptographic Hashing**: Computes MD5 and SHA-256 hashes.
3. **Metadata Extraction**: Measures file size and identifies Windows PE executables versus document/script files.
4. **Static Indicator Scanning**: Checks for suspicious command-line strings (e.g., `powershell`, `cmd.exe`, `vssadmin`, embedded URLs).
5. **Risk Scoring**: Generates a risk score (0 to 100) and assigns a verdict (`BENIGN`, `SUSPICIOUS`, or `MALWARE`).
6. **Data Persistence**: Records scan metadata into an SQLite database (`database.db`).

### API Endpoints

#### Upload & Analyze File
`POST /api/upload`

Form Data:
- `file`: (binary payload)
- `username`: (optional string)

Example Response:
```json
{
  "scan_id": "SCAN-8F2A1C",
  "filename": "suspicious_installer.exe",
  "file_size": 1024,
  "file_type": "Windows Executable (.exe)",
  "hashes": {
    "md5": "e10adc3949ba59abbe56e057f20f883e",
    "sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
  },
  "static_analysis": {
    "suspicious_indicators": [
      "Command shell execution command found"
    ],
    "is_executable": true
  },
  "result": {
    "risk_score": 50,
    "verdict": "SUSPICIOUS",
    "recommended_action": "Allow Execution"
  },
  "uploaded_by": "analyst_demo",
  "timestamp": "2026-08-05 14:30:00"
}
```

#### List Scans History
`GET /api/scans`

---

## How to Run

1. **Install dependencies**:
   ```bash
   pip install fastapi uvicorn python-multipart
   ```

2. **Run the server**:
   ```bash
   uvicorn main:app --reload --port 8000
   ```

3. **Access Interactive API Docs**:
   Open browser at: `http://localhost:8000/docs`
