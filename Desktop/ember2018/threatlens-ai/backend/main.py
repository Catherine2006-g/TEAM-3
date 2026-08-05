import os
import hashlib
import uuid
import datetime
import sqlite3
import json
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr

# Initialize FastAPI App
app = FastAPI(
    title="ThreatLens AI - Basic Auth & File Upload API",
    description="Basic implementation of Authentication (User & Role Management) and File Upload Static Analysis (Hashing & Basic Indicator Scan)",
    version="0.2.0"
)

# Paths setup
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
DB_PATH = BASE_DIR / "database.db"

# Simple SQLite Database Setup
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Table 1: Users table for Authentication & Roles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT
        )
    ''')
    
    # Table 2: Scans table for Uploaded Files & Static Analysis
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_scans (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            md5 TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            uploaded_by TEXT NOT NULL,
            upload_time TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

# Run database setup on startup
init_db()


# -------------------------------------------------------------
# 1. USER AUTHENTICATION & ROLE MANAGEMENT MODULE
# -------------------------------------------------------------

class UserRegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "Security Analyst"  # Roles: Security Analyst, SOC Team Member, Administrator, Researcher
    full_name: Optional[str] = ""

class UserLoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/register")
def register_user(user_data: UserRegisterRequest):
    """
    Register a new user with chosen role
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_data.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username is already taken")
        
    cursor.execute(
        "INSERT INTO users (username, email, password, role, full_name) VALUES (?, ?, ?, ?, ?)",
        (user_data.username, user_data.email, user_data.password, user_data.role, user_data.full_name)
    )
    conn.commit()
    conn.close()
    
    return {
        "status": "success",
        "message": f"User '{user_data.username}' registered successfully",
        "user": {
            "username": user_data.username,
            "email": user_data.email,
            "role": user_data.role
        }
    }


@app.post("/api/login")
def login_user(login_data: UserLoginRequest):
    """
    Authenticate user and return user info & token
    """
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (login_data.username, login_data.password)
    )
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    user = dict(row)
    
    # Simple token generation for basic auth
    token = f"token_{user['username']}_{uuid.uuid4().hex[:8]}"
    
    return {
        "status": "success",
        "access_token": token,
        "user": {
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user["full_name"]
        }
    }


@app.get("/api/me")
def get_user_profile(username: str = "analyst_demo"):
    """
    Get profile of logged in user
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, role, full_name FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return {
            "username": username,
            "email": f"{username}@threatlens.ai",
            "role": "Security Analyst",
            "full_name": "Demo Security Analyst"
        }
        
    return dict(row)


# -------------------------------------------------------------
# 2. FILE UPLOAD & BASIC STATIC ANALYSIS MODULE
# -------------------------------------------------------------

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), username: str = "analyst_demo"):
    """
    Upload suspicious file and run basic static file analysis:
    - Save file
    - Compute MD5 & SHA-256 hashes
    - Check file size & basic file type
    - Scan for suspicious string indicators
    - Compute basic risk score (0-100)
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename cannot be empty")
        
    # Save uploaded file
    file_bytes = await file.read()
    file_size = len(file_bytes)
    
    saved_filename = f"{uuid.uuid4().hex[:6]}_{file.filename}"
    file_path = UPLOAD_DIR / saved_filename
    file_path.write_bytes(file_bytes)
    
    # Calculate Hashes
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # File Type Identification
    is_exe = file_bytes.startswith(b"MZ")
    file_type = "Windows Executable (.exe)" if is_exe else "Document / Script File"
    
    # Basic Static Analysis - Check suspicious strings
    suspicious_indicators = []
    content_lower = file_bytes.lower()
    
    if b"powershell" in content_lower or b"cmd.exe" in content_lower:
        suspicious_indicators.append("Command shell execution command found")
    if b"vssadmin" in content_lower or b"bcdedit" in content_lower:
        suspicious_indicators.append("Ransomware shadow copy deletion command found")
    if b"http://" in content_lower or b"https://" in content_lower:
        suspicious_indicators.append("Embedded network URL found")
        
    # Calculate basic Risk Score
    if len(suspicious_indicators) >= 2:
        risk_score = 85
        verdict = "MALWARE"
    elif len(suspicious_indicators) == 1 or is_exe:
        risk_score = 50
        verdict = "SUSPICIOUS"
    else:
        risk_score = 15
        verdict = "BENIGN"
        
    scan_id = f"SCAN-{uuid.uuid4().hex[:6].upper()}"
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Save scan record to SQLite DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO file_scans (id, filename, file_size, md5, sha256, verdict, risk_score, uploaded_by, upload_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, file.filename, file_size, md5_hash, sha256_hash, verdict, risk_score, username, now_str)
    )
    conn.commit()
    conn.close()
    
    return {
        "scan_id": scan_id,
        "filename": file.filename,
        "file_size": file_size,
        "file_type": file_type,
        "hashes": {
            "md5": md5_hash,
            "sha256": sha256_hash
        },
        "static_analysis": {
            "suspicious_indicators": suspicious_indicators,
            "is_executable": is_exe
        },
        "result": {
            "risk_score": risk_score,
            "verdict": verdict,
            "recommended_action": "Quarantine File" if risk_score > 50 else "Allow Execution"
        },
        "uploaded_by": username,
        "timestamp": now_str
    }


@app.get("/api/scans")
def list_scans():
    """
    List history of uploaded file scans
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scans ORDER BY upload_time DESC")
    rows = cursor.fetchall()
    conn.close()
    
    return {
        "total_scans": len(rows),
        "scans": [dict(r) for r in rows]
    }


@app.get("/")
def home():
    return {
        "message": "ThreatLens AI - Basic Auth & File Upload Backend",
        "status": "online",
        "part": "2 / 10 Basic Modules",
        "docs": "/docs"
    }
