import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# Add workspace root to sys.path for ml_engine imports
root_dir = backend_dir.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    print("[PASS] Health Check")

def test_register():
    payload = {
        "username": "analyst_modular",
        "email": "analyst@threatlens.ai",
        "password": "SecurePassword123!",
        "role": "Security Analyst",
        "full_name": "Modular Security Analyst"
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["username"] == "analyst_modular"
    assert data["user"]["role"] == "Security Analyst"
    print("[PASS] User Registration")

def test_login():
    payload = {
        "username": "analyst_modular",
        "password": "SecurePassword123!"
    }
    response = client.post("/api/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    print("[PASS] User Login & Token Generation")

def test_profile():
    response = client.get("/api/auth/me?username=analyst_modular")
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "analyst_modular"
    print("[PASS] Profile Lookup")

def test_file_upload_scan():
    sample_content = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"powershell -ExecutionPolicy Bypass -enc SQBFAFgA\x00"
        b"http://malicious-domain.com/payload.exe\x00"
    )
    files = {
        "file": ("suspicious_invoice.exe", sample_content, "application/octet-stream")
    }
    response = client.post("/api/upload/scan?username=analyst_modular", files=files)
    assert response.status_code == 200
    data = response.json()
    
    assert "scan_id" in data
    assert data["filename"] == "suspicious_invoice.exe"
    assert "sha256" in data["hashes"]
    assert data["detection"]["risk_score"] > 0
    print(f"[PASS] File Upload & Static Analysis (Risk Score: {data['detection']['risk_score']}/100, Verdict: {data['detection']['verdict']})")

def test_list_scans():
    response = client.get("/api/upload/scans")
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] >= 1
    print(f"[PASS] List Scans History (Total: {data['total_scans']})")

if __name__ == "__main__":
    print("=== Testing Modularized ThreatLens AI Backend (Review 1) ===")
    test_health()
    test_register()
    test_login()
    test_profile()
    test_file_upload_scan()
    test_list_scans()
    print("=== ALL TESTS PASSED SUCCESSFULLY! ===")
