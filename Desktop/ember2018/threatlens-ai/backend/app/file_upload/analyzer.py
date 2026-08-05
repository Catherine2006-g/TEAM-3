import os
import hashlib
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any

# Optional YARA scanner import
try:
    from ml_engine.engine.yara_scanner import scan_with_yara
    HAS_YARA = True
except Exception:
    HAS_YARA = False

def run_basic_static_analysis(file_path: Path, filename: str, username: str) -> Dict[str, Any]:
    """
    Perform core basic static analysis on uploaded file:
    - Compute MD5 & SHA-256 hashes
    - Measure file size & determine file type
    - Scan for suspicious command strings & YARA matches
    - Compute basic risk score (0 - 100)
    """
    file_bytes = file_path.read_bytes()
    file_size = len(file_bytes)
    
    # 1. Hashing
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # 2. File Type Identification
    file_ext = file_path.suffix.lower()
    is_exe = file_bytes.startswith(b"MZ")
    file_type = "Windows Executable (.exe)" if is_exe else f"File ({file_ext.upper() if file_ext else 'Binary'})"
    
    # 3. YARA Rule Scanning
    yara_matches = []
    if HAS_YARA:
        try:
            res = scan_with_yara(str(file_path))
            if res.get("matched"):
                yara_matches = res.get("matched_rules", [])
        except Exception:
            pass
            
    # 4. Basic String Indicators
    suspicious_indicators = []
    content_lower = file_bytes.lower()
    
    if b"powershell" in content_lower or b"cmd.exe" in content_lower:
        suspicious_indicators.append("Command shell execution string found")
    if b"vssadmin" in content_lower or b"bcdedit" in content_lower:
        suspicious_indicators.append("Ransomware shadow copy removal string found")
    if b"http://" in content_lower or b"https://" in content_lower:
        suspicious_indicators.append("Embedded remote network URL found")
        
    # 5. Risk Scoring & Verdict
    if yara_matches or len(suspicious_indicators) >= 2:
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
    
    return {
        "scan_id": scan_id,
        "filename": filename,
        "file_size": file_size,
        "file_type": file_type,
        "hashes": {
            "md5": md5_hash,
            "sha256": sha256_hash
        },
        "static_analysis": {
            "yara_matches": yara_matches,
            "suspicious_indicators": suspicious_indicators,
            "is_executable": is_exe
        },
        "detection": {
            "risk_score": risk_score,
            "verdict": verdict,
            "recommended_action": "Quarantine File" if risk_score > 50 else "Allow Execution"
        },
        "uploaded_by": username,
        "timestamp": now_str
    }
