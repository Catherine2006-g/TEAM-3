import uuid
import shutil
import os
import datetime
import hashlib
import json
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, status, Depends, BackgroundTasks
from app.config import UPLOAD_DIR
from app.database import get_db
from app.auth.router import get_current_user, require_roles
from app.file_upload.analyzer import run_basic_static_analysis, process_async_scan, run_dynamic_sandbox_analysis
from app.file_upload.schemas import (
    ScanResponse,
    AsyncScanResponse,
    SandboxTriggerResponse,
    ScanListResponse,
    ScanItemResponse,
    MessageResponse
)
from app.audit.service import log_audit_event

router = APIRouter(prefix="/api/upload", tags=["File Upload & Static/Dynamic Analysis"])

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit
ALLOWED_UPLOAD_ROLES = ["Administrator", "Security Analyst", "Researcher"]

@router.post("/scan", response_model=ScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles(ALLOWED_UPLOAD_ROLES))
):
    """
    Upload suspicious file, sanitize inputs, enforce size limits,
    perform static analysis, and persist scan output.
    RBAC: Restricted to Administrator, Security Analyst, Researcher.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename cannot be empty.")
        
    safe_filename = Path(file.filename).name
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename provided.")
        
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        log_audit_event(current_user["username"], current_user["role"], "FILE_UPLOAD", safe_filename, "Rejected 0-byte file", "FAILED")
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")
        
    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        log_audit_event(current_user["username"], current_user["role"], "FILE_UPLOAD", safe_filename, f"Exceeded size limit: {len(file_bytes)} bytes", "FAILED")
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds maximum allowed limit of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB."
        )

    saved_filename = f"{uuid.uuid4().hex[:6]}_{safe_filename}"
    file_path = UPLOAD_DIR / saved_filename
    file_path.write_bytes(file_bytes)
    
    username = current_user.get("username", "authenticated_user")
    
    try:
        result = run_basic_static_analysis(file_path, safe_filename, username)
        ml_data = result.get("static_analysis", {}).get("ml_engine", {})
        conf_score = (ml_data.get("malware_probability", 0.0) / 100.0) if ml_data else 0.85
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO file_scans (id, filename, file_path, file_size, file_type, md5, sha256, status, verdict, risk_score, confidence_score, static_analysis_json, uploaded_by, upload_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["scan_id"],
                result["filename"],
                str(file_path),
                result["file_size"],
                result["file_type"],
                result["hashes"]["md5"],
                result["hashes"]["sha256"],
                "COMPLETED",
                result["detection"]["verdict"],
                result["detection"]["risk_score"],
                conf_score,
                json.dumps(result["static_analysis"]),
                username,
                result["timestamp"]
            )
        )
        conn.commit()
        conn.close()
        
        log_audit_event(username, current_user["role"], "FILE_UPLOAD_SCAN", result["scan_id"], f"Uploaded & scanned '{safe_filename}' - Verdict: {result['detection']['verdict']}", "SUCCESS")
        
        return result
    except Exception as e:
        log_audit_event(username, current_user["role"], "FILE_UPLOAD_SCAN", safe_filename, f"Static analysis error: {str(e)}", "FAILED")
        raise HTTPException(status_code=500, detail=f"File analysis error: {str(e)}")

@router.post("/scan/async", response_model=AsyncScanResponse)
async def scan_file_async(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles(ALLOWED_UPLOAD_ROLES))
):
    """
    Milestone 3 Asynchronous EMBER Pipeline:
    Upload file for background asynchronous feature extraction & scanning.
    Returns immediately with PENDING scan_id while processing runs in background.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename cannot be empty.")
        
    safe_filename = Path(file.filename).name
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")
        
    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File size exceeds 50MB limit.")

    saved_filename = f"async_{uuid.uuid4().hex[:6]}_{safe_filename}"
    file_path = UPLOAD_DIR / saved_filename
    file_path.write_bytes(file_bytes)
    
    scan_id = f"SCAN-{uuid.uuid4().hex[:6].upper()}"
    username = current_user.get("username", "authenticated_user")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    is_exe = file_bytes.startswith(b"MZ")
    file_type = "Windows Executable (.exe)" if is_exe else "Binary"
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO file_scans (id, filename, file_path, file_size, file_type, md5, sha256, status, verdict, risk_score, confidence_score, uploaded_by, upload_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', 0, 0.0, ?, ?)
        """,
        (scan_id, safe_filename, str(file_path), len(file_bytes), file_type, md5_hash, sha256_hash, username, now_str)
    )
    conn.commit()
    conn.close()
    
    # Schedule background async worker task
    background_tasks.add_task(process_async_scan, scan_id, file_path, safe_filename, username)
    
    log_audit_event(username, current_user["role"], "ASYNC_SCAN_SUBMIT", scan_id, f"Submitted '{safe_filename}' for background EMBER analysis", "SUCCESS")
    
    return {
        "scan_id": scan_id,
        "filename": safe_filename,
        "status": "PENDING",
        "message": "File upload accepted. Asynchronous EMBER feature extraction is running in background."
    }

@router.post("/scans/{scan_id}/sandbox", response_model=SandboxTriggerResponse)
def trigger_sandbox_analysis(
    scan_id: str,
    current_user: dict = Depends(require_roles(ALLOWED_UPLOAD_ROLES))
):
    """
    Milestone 4 Sandbox Dynamic Analysis Trigger:
    Executes dynamic behavioral analysis for an uploaded executable file scan.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
        
    scan_record = dict(row)
    filename = scan_record["filename"]
    
    # Locate exact file using stored file_path or fallback to directory matching
    stored_path_str = scan_record.get("file_path")
    if stored_path_str and Path(stored_path_str).exists():
        file_path = Path(stored_path_str)
    else:
        matching_files = list(UPLOAD_DIR.glob(f"*_{filename}"))
        file_path = matching_files[0] if matching_files else UPLOAD_DIR / filename
    
    dynamic_res = run_dynamic_sandbox_analysis(scan_id, file_path)
    
    log_audit_event(current_user["username"], current_user["role"], "SANDBOX_TRIGGER", scan_id, f"Triggered sandbox analysis for '{filename}' - Dynamic Risk: {dynamic_res['dynamic_risk_score']}/100", "SUCCESS")
    
    return {
        "scan_id": scan_id,
        "sandbox_status": "ANALYSIS_COMPLETED",
        "dynamic_analysis": dynamic_res
    }

@router.get("/scans", response_model=ScanListResponse)
def list_scans(current_user: dict = Depends(get_current_user)):
    """Retrieve history of uploaded file scans (Requires Authentication)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scans ORDER BY upload_time DESC")
    rows = cursor.fetchall()
    conn.close()
    
    scans_list = []
    for r in rows:
        item = dict(r)
        if item.get("static_analysis_json"):
            try:
                item["static_analysis"] = json.loads(item["static_analysis_json"])
            except Exception:
                pass
        if item.get("dynamic_analysis_json"):
            try:
                item["dynamic_analysis"] = json.loads(item["dynamic_analysis_json"])
            except Exception:
                pass
        scans_list.append(item)
        
    return {
        "total_scans": len(scans_list),
        "scans": scans_list
    }

@router.get("/scans/{scan_id}", response_model=ScanItemResponse)
def get_scan_detail(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Retrieve details for a specific scan ID"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
        
    item = dict(row)
    if item.get("static_analysis_json"):
        try:
            item["static_analysis"] = json.loads(item["static_analysis_json"])
        except Exception:
            pass
    if item.get("dynamic_analysis_json"):
        try:
            item["dynamic_analysis"] = json.loads(item["dynamic_analysis_json"])
        except Exception:
            pass
            
    return item

@router.delete("/scans/{scan_id}", response_model=MessageResponse)
def delete_scan(
    scan_id: str,
    current_user: dict = Depends(require_roles(["Administrator"]))
):
    """
    Delete scan record by scan ID (Milestone 4 RBAC: Restricted to Administrator ONLY)
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
        
    cursor.execute("DELETE FROM file_scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    
    log_audit_event(current_user["username"], current_user["role"], "DELETE_SCAN", scan_id, f"Deleted scan record '{scan_id}'", "SUCCESS")
    
    return {
        "status": "success",
        "message": f"Scan record '{scan_id}' deleted successfully by Administrator."
    }


