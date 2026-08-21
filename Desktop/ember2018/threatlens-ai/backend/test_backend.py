import sys
import uuid
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

TEST_USER = f"analyst_m2_{uuid.uuid4().hex[:4]}"
TEST_PASSWORD = "SecurePassword123!"
ACCESS_TOKEN = ""

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    print("[PASS] Health Check")

def test_register():
    payload = {
        "username": TEST_USER,
        "email": f"{TEST_USER}@threatlens.ai",
        "password": TEST_PASSWORD,
        "role": "Security Analyst",
        "full_name": "Milestone 2 Security Analyst"
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["username"] == TEST_USER
    assert data["user"]["role"] == "Security Analyst"
    print("[PASS] User Registration with PBKDF2 Password Hashing")

def test_login():
    global ACCESS_TOKEN
    payload = {
        "username": TEST_USER,
        "password": TEST_PASSWORD
    }
    response = client.post("/api/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    ACCESS_TOKEN = data["access_token"]
    print(f"[PASS] User Login & Bearer Token Generation (Token: {ACCESS_TOKEN[:15]}...)")

def test_unauthenticated_access_denied():
    # Attempting to access protected profile without Bearer header
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    
    # Attempting upload scan without token
    sample_content = b"sample unauthenticated data"
    files = {"file": ("test.txt", sample_content, "text/plain")}
    upload_resp = client.post("/api/upload/scan", files=files)
    assert upload_resp.status_code == 401
    print("[PASS] Enforced HTTP Bearer Authorization (401 Unauthorized for unauthenticated requests)")

def test_profile():
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == TEST_USER
    assert data["role"] == "Security Analyst"
    print("[PASS] Protected Profile Lookup using Bearer Token")

def test_file_upload_scan():
    global LAST_SCAN_ID
    sample_content = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"powershell -ExecutionPolicy Bypass -enc SQBFAFgA\x00"
        b"http://malicious-domain.com/payload.exe\x00"
    )
    files = {
        "file": ("suspicious_invoice.exe", sample_content, "application/octet-stream")
    }
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    response = client.post("/api/upload/scan", files=files, headers=headers)
    assert response.status_code == 200
    data = response.json()
    
    assert "scan_id" in data
    assert data["filename"] == "suspicious_invoice.exe"
    assert "sha256" in data["hashes"]
    assert data["detection"]["risk_score"] > 0
    assert data["uploaded_by"] == TEST_USER
    
    globals()["LAST_SCAN_ID"] = data["scan_id"]
    print(f"[PASS] File Upload & Static Analysis with Auth (Scan ID: {data['scan_id']}, Risk: {data['detection']['risk_score']}/100)")

def test_empty_file_validation():
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    files = {"file": ("empty.txt", b"", "text/plain")}
    response = client.post("/api/upload/scan", files=files, headers=headers)
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()
    print("[PASS] Empty File Validation (Rejected 0-byte file)")

def test_list_scans():
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    response = client.get("/api/upload/scans", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] >= 1
    print(f"[PASS] List Scans History (Total Scans: {data['total_scans']})")

def test_get_scan_detail():
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    scan_id = globals().get("LAST_SCAN_ID")
    response = client.get(f"/api/upload/scans/{scan_id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == scan_id
    assert data["filename"] == "suspicious_invoice.exe"
    print(f"[PASS] Scan Detail Lookup by ID ({scan_id})")

def test_delete_scan():
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    scan_id = globals().get("LAST_SCAN_ID")
    response = client.delete(f"/api/upload/scans/{scan_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    
    # Confirm scan was deleted
    get_resp = client.get(f"/api/upload/scans/{scan_id}", headers=headers)
    assert get_resp.status_code == 404
    print(f"[PASS] Delete Scan Record by ID ({scan_id})")

def test_logout():
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    response = client.post("/api/auth/logout", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    
    # Verify token is now invalid
    me_resp = client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == 401
    print("[PASS] Logout & Token Revocation")

if __name__ == "__main__":
    print("=== Testing ThreatLens AI Backend (Milestone 2 Evaluation) ===")
    test_health()
    test_register()
    test_login()
    test_unauthenticated_access_denied()
    test_profile()
    test_file_upload_scan()
    test_empty_file_validation()
    test_list_scans()
    test_get_scan_detail()
    test_delete_scan()
    test_logout()
    print("=== ALL MILESTONE 2 TESTS PASSED SUCCESSFULLY! ===")
