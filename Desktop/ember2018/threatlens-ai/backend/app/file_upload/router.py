import uuid
import shutil
import os
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, status, Depends
from app.config import UPLOAD_DIR
from app.database import get_db
from app.auth.router import get_current_user
from app.file_upload.analyzer import run_basic_static_analysis

router = APIRouter(prefix="/api/upload", tags=["File Upload & Static File Analysis"])

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit

@router.post("/scan")
async def scan_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Upload suspicious file, sanitize inputs, enforce size limits,
    perform static analysis, and persist scan output.
    Requires Bearer Token authentication.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename cannot be empty.")
        
    # Sanitize filename to prevent directory traversal
    safe_filename = Path(file.filename).name
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename provided.")
        
    # Read file content and validate size limit
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")
        
    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
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
        
        # Store scan summary in SQLite database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO file_scans (id, filename, file_size, file_type, md5, sha256, verdict, risk_score, uploaded_by, upload_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result["scan_id"],
                result["filename"],
                result["file_size"],
                result["file_type"],
                result["hashes"]["md5"],
                result["hashes"]["sha256"],
                result["detection"]["verdict"],
                result["detection"]["risk_score"],
                username,
                result["timestamp"]
            )
        )
        conn.commit()
        conn.close()
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File analysis error: {str(e)}")

@router.get("/scans")
def list_scans(current_user: dict = Depends(get_current_user)):
    """Retrieve history of uploaded file scans (Requires Authentication)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scans ORDER BY upload_time DESC")
    rows = cursor.fetchall()
    conn.close()
    
    return {
        "total_scans": len(rows),
        "scans": [dict(r) for r in rows]
    }

@router.get("/scans/{scan_id}")
def get_scan_detail(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Retrieve details for a specific scan ID"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
        
    return dict(row)

@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Delete scan record by scan ID"""
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
    
    return {
        "status": "success",
        "message": f"Scan record '{scan_id}' deleted successfully."
    }
