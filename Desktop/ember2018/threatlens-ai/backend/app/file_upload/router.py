import uuid
import shutil
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.config import UPLOAD_DIR
from app.database import get_db
from app.file_upload.analyzer import run_basic_static_analysis

router = APIRouter(prefix="/api/upload", tags=["File Upload & Static File Analysis"])

@router.post("/scan")
async def scan_file(file: UploadFile = File(...), username: str = "analyst_demo"):
    """Upload suspicious file, perform static analysis, and record scan output"""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename cannot be empty.")
        
    saved_filename = f"{uuid.uuid4().hex[:6]}_{file.filename}"
    file_path = UPLOAD_DIR / saved_filename
    
    # Save file contents
    file_bytes = await file.read()
    file_path.write_bytes(file_bytes)
    
    try:
        result = run_basic_static_analysis(file_path, file.filename, username)
        
        # Store scan summary in database
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
def list_scans():
    """Retrieve history of uploaded file scans"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scans ORDER BY upload_time DESC")
    rows = cursor.fetchall()
    conn.close()
    
    return {
        "total_scans": len(rows),
        "scans": [dict(r) for r in rows]
    }
