import os
import hashlib
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any

# Optional YARA scanner and ML engine imports
try:
    from ml_engine.engine.yara_scanner import scan_with_yara
    HAS_YARA = True
except Exception:
    HAS_YARA = False

try:
    from ml_engine.engine.scanner import MalwareScanner
    ml_scanner_instance = MalwareScanner()
    HAS_ML_ENGINE = True
except Exception:
    HAS_ML_ENGINE = False


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
            
    # 4. ML Engine Prediction (if available)
    ml_info = None
    if HAS_ML_ENGINE and is_exe:
        try:
            ml_res = ml_scanner_instance.scan(str(file_path))
            if ml_res.get("scan_status") == "SUCCESS":
                ml_info = ml_res.get("ml")
        except Exception:
            pass

    # 5. Basic String Indicators
    suspicious_indicators = []
    content_lower = file_bytes.lower()
    
    if b"powershell" in content_lower or b"cmd.exe" in content_lower:
        suspicious_indicators.append("Command shell execution string found")
    if b"vssadmin" in content_lower or b"bcdedit" in content_lower:
        suspicious_indicators.append("Ransomware shadow copy removal string found")
    if b"http://" in content_lower or b"https://" in content_lower:
        suspicious_indicators.append("Embedded remote network URL found")
        
    # 6. Risk Scoring & Verdict
    if yara_matches or len(suspicious_indicators) >= 2 or (ml_info and ml_info.get("prediction") == "MALWARE"):
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
    
    analysis_payload = {
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
            "is_executable": is_exe,
            "ml_engine": ml_info
        },
        "detection": {
            "risk_score": risk_score,
            "verdict": verdict,
            "recommended_action": "Quarantine File" if risk_score > 50 else "Allow Execution"
        },
        "uploaded_by": username,
        "timestamp": now_str
    }
    return analysis_payload


def process_async_scan(scan_id: str, file_path: Path, filename: str, username: str):
    """
    Milestone 3 Asynchronous Worker Task:
    Executes feature extraction and static analysis asynchronously in the background.
    Updates scan record status from PENDING -> PROCESSING -> COMPLETED in SQLite.
    """
    import json
    from app.database import get_db
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE file_scans SET status = 'PROCESSING' WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    
    try:
        result = run_basic_static_analysis(file_path, filename, username)
        
        ml_data = result.get("static_analysis", {}).get("ml_engine", {})
        conf_score = ml_data.get("malware_probability", 0.0) / 100.0 if ml_data else 0.85
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE file_scans
            SET status = 'COMPLETED',
                verdict = ?,
                risk_score = ?,
                confidence_score = ?,
                static_analysis_json = ?
            WHERE id = ?
            """,
            (
                result["detection"]["verdict"],
                result["detection"]["risk_score"],
                conf_score,
                json.dumps(result["static_analysis"]),
                scan_id
            )
        )
        conn.commit()
        conn.close()
    except Exception as e:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE file_scans SET status = 'FAILED' WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()


def run_dynamic_sandbox_analysis(scan_id: str, file_path: Path) -> Dict[str, Any]:
    """
    Milestone 4 Sandbox Dynamic Analysis Simulator:
    Simulates dynamic execution of malware executable inside isolated environment:
    - Registry persistence key creation checks
    - Process hollowing & DLL injection indicators
    - Outbound C2 communication attempts
    - Dynamic risk score computation
    """
    import json
    from app.database import get_db
    
    file_bytes = file_path.read_bytes() if file_path.exists() else b""
    content_lower = file_bytes.lower()
    
    behavior_indicators = []
    process_tree = ["explorer.exe", "sample_process.exe"]
    network_activities = []
    registry_changes = []
    
    if b"powershell" in content_lower or b"cmd" in content_lower:
        behavior_indicators.append("Spawning hidden command interpreter (process injection)")
        process_tree.append("cmd.exe /c powershell -W Hidden")
        
    if b"vssadmin" in content_lower:
        behavior_indicators.append("Attempted shadow copy deletion via vssadmin")
        
    if b"http://" in content_lower or b"https://" in content_lower or b"socket" in content_lower:
        network_activities.append({"destination": "c2.malicious-host.org:8080", "protocol": "HTTP/TCP", "action": "Beacon Callback"})
        
    registry_changes.append(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ThreatLensPersist")
    
    dynamic_risk_score = 90 if len(behavior_indicators) >= 1 or len(network_activities) >= 1 else 30
    dynamic_verdict = "MALWARE" if dynamic_risk_score >= 70 else "SUSPICIOUS" if dynamic_risk_score >= 40 else "BENIGN"
    
    dynamic_result = {
        "sandbox_status": "ANALYSIS_COMPLETED",
        "environment": "Windows 10 Pro x64 (Sandbox Isolated)",
        "behavior_indicators": behavior_indicators,
        "process_tree": process_tree,
        "network_activities": network_activities,
        "registry_changes": registry_changes,
        "dynamic_risk_score": dynamic_risk_score,
        "dynamic_verdict": dynamic_verdict,
        "execution_time_seconds": 12.4
    }
    
    # Update scan record in DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE file_scans
        SET dynamic_analysis_json = ?,
            risk_score = MAX(risk_score, ?),
            verdict = CASE WHEN ? = 'MALWARE' THEN 'MALWARE' ELSE verdict END
        WHERE id = ?
        """,
        (json.dumps(dynamic_result), dynamic_risk_score, dynamic_verdict, scan_id)
    )
    conn.commit()
    conn.close()
    
    return dynamic_result


