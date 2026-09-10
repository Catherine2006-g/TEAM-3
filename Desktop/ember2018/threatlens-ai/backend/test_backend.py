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

TEST_USER = f"analyst_m4_{uuid.uuid4().hex[:4]}"
ADMIN_USER = f"admin_m4_{uuid.uuid4().hex[:4]}"
SOC_USER = f"soc_m4_{uuid.uuid4().hex[:4]}"
TEST_PASSWORD = "SecurePassword123!"

ANALYST_ACCESS_TOKEN = ""
ANALYST_REFRESH_TOKEN = ""
ADMIN_ACCESS_TOKEN = ""
SOC_ACCESS_TOKEN = ""
LAST_SCAN_ID = ""

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "Milestone 1 through Milestone 4 Complete" in data["milestones"]
    print("[PASS] Health Check (Milestone 1-4 Verification)")

def test_register():
    # 1. Register Security Analyst
    resp_analyst = client.post("/api/auth/register", json={
        "username": TEST_USER,
        "email": f"{TEST_USER}@threatlens.ai",
        "password": TEST_PASSWORD,
        "role": "Security Analyst",
        "full_name": "Milestone 4 Analyst"
    })
    assert resp_analyst.status_code == 200

    # 2. Register Administrator
    resp_admin = client.post("/api/auth/register", json={
        "username": ADMIN_USER,
        "email": f"{ADMIN_USER}@threatlens.ai",
        "password": TEST_PASSWORD,
        "role": "Administrator",
        "full_name": "System Administrator"
    })
    assert resp_admin.status_code == 200

    # 3. Register SOC Team Member
    resp_soc = client.post("/api/auth/register", json={
        "username": SOC_USER,
        "email": f"{SOC_USER}@threatlens.ai",
        "password": TEST_PASSWORD,
        "role": "SOC Team Member",
        "full_name": "SOC Incident Handler"
    })
    assert resp_soc.status_code == 200
    print("[PASS] User Registration with Role Assignments (Analyst, Admin, SOC Member)")

def test_login():
    global ANALYST_ACCESS_TOKEN, ANALYST_REFRESH_TOKEN, ADMIN_ACCESS_TOKEN, SOC_ACCESS_TOKEN
    
    # Login Analyst
    res_analyst = client.post("/api/auth/login", json={"username": TEST_USER, "password": TEST_PASSWORD}).json()
    assert "access_token" in res_analyst and "refresh_token" in res_analyst
    ANALYST_ACCESS_TOKEN = res_analyst["access_token"]
    ANALYST_REFRESH_TOKEN = res_analyst["refresh_token"]

    # Login Admin
    res_admin = client.post("/api/auth/login", json={"username": ADMIN_USER, "password": TEST_PASSWORD}).json()
    ADMIN_ACCESS_TOKEN = res_admin["access_token"]

    # Login SOC Member
    res_soc = client.post("/api/auth/login", json={"username": SOC_USER, "password": TEST_PASSWORD}).json()
    SOC_ACCESS_TOKEN = res_soc["access_token"]

    print("[PASS] User Login & Paired Access/Refresh Token Generation")

def test_refresh_token_rotation():
    global ANALYST_ACCESS_TOKEN, ANALYST_REFRESH_TOKEN
    
    response = client.post("/api/auth/refresh", json={"refresh_token": ANALYST_REFRESH_TOKEN})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data and "refresh_token" in data
    assert data["refresh_token"] != ANALYST_REFRESH_TOKEN
    
    old_refresh = ANALYST_REFRESH_TOKEN
    ANALYST_ACCESS_TOKEN = data["access_token"]
    ANALYST_REFRESH_TOKEN = data["refresh_token"]
    
    # Attempting reuse of old refresh token must fail (Rotation Security)
    reuse_resp = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    assert reuse_resp.status_code == 401
    print("[PASS] Milestone 3: Refresh Token Rotation & Replay Protection")

def test_unauthenticated_access_denied():
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    print("[PASS] Enforced HTTP Bearer Authorization (401 Unauthorized)")

def test_file_upload_scan():
    global LAST_SCAN_ID
    sample_content = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"powershell -ExecutionPolicy Bypass -enc SQBFAFgA\x00"
        b"http://malicious-domain.com/payload.exe\x00"
    )
    files = {"file": ("suspicious_invoice.exe", sample_content, "application/octet-stream")}
    headers = {"Authorization": f"Bearer {ANALYST_ACCESS_TOKEN}"}
    response = client.post("/api/upload/scan", files=files, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    LAST_SCAN_ID = data["scan_id"]
    print(f"[PASS] Synchronous File Upload & Static ML Scan (Scan ID: {LAST_SCAN_ID})")

def test_async_scan_processing():
    sample_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00cmd.exe /c vssadmin"
    files = {"file": ("background_payload.exe", sample_content, "application/octet-stream")}
    headers = {"Authorization": f"Bearer {ANALYST_ACCESS_TOKEN}"}
    response = client.post("/api/upload/scan/async", files=files, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["PENDING", "PROCESSING", "COMPLETED"]
    
    # Check details endpoint
    async_id = data["scan_id"]
    detail_resp = client.get(f"/api/upload/scans/{async_id}", headers=headers)
    assert detail_resp.status_code == 200
    print(f"[PASS] Milestone 3: Asynchronous Background Scan Pipeline (Scan ID: {async_id})")

def test_sandbox_dynamic_analysis():
    headers = {"Authorization": f"Bearer {ANALYST_ACCESS_TOKEN}"}
    response = client.post(f"/api/upload/scans/{LAST_SCAN_ID}/sandbox", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["sandbox_status"] == "ANALYSIS_COMPLETED"
    assert "dynamic_analysis" in data
    assert data["dynamic_analysis"]["dynamic_risk_score"] > 0
    print(f"[PASS] Milestone 4: Trigger Sandbox Dynamic Behavioral Analysis (Scan ID: {LAST_SCAN_ID})")

def test_rbac_matrix_enforcement():
    # 1. SOC Team Member attempt file upload -> Must fail (403 Forbidden)
    soc_headers = {"Authorization": f"Bearer {SOC_ACCESS_TOKEN}"}
    files = {"file": ("soc_test.exe", b"MZ\x90\x00", "application/octet-stream")}
    soc_upload_resp = client.post("/api/upload/scan", files=files, headers=soc_headers)
    assert soc_upload_resp.status_code == 403

    # 2. Security Analyst attempt scan delete -> Must fail (403 Forbidden)
    analyst_headers = {"Authorization": f"Bearer {ANALYST_ACCESS_TOKEN}"}
    analyst_del_resp = client.delete(f"/api/upload/scans/{LAST_SCAN_ID}", headers=analyst_headers)
    assert analyst_del_resp.status_code == 403

    # 3. Security Analyst attempt audit logs view -> Must fail (403 Forbidden)
    analyst_audit_resp = client.get("/api/audit/logs", headers=analyst_headers)
    assert analyst_audit_resp.status_code == 403

    # 4. Administrator attempt audit logs view -> Must succeed (200 OK)
    admin_headers = {"Authorization": f"Bearer {ADMIN_ACCESS_TOKEN}"}
    admin_audit_resp = client.get("/api/audit/logs", headers=admin_headers)
    assert admin_audit_resp.status_code == 200
    assert admin_audit_resp.json()["total_logs"] > 0

    # 5. Administrator attempt scan delete -> Must succeed (200 OK)
    admin_del_resp = client.delete(f"/api/upload/scans/{LAST_SCAN_ID}", headers=admin_headers)
    assert admin_del_resp.status_code == 200

    print("[PASS] Milestone 4: RBAC Matrix & Governance Enforcement (Analyst, SOC, Admin)")

def test_logout():
    global ANALYST_ACCESS_TOKEN
    headers = {"Authorization": f"Bearer {ANALYST_ACCESS_TOKEN}"}
    response = client.post("/api/auth/logout", headers=headers)
    assert response.status_code == 200
    
    # Requesting protected endpoint with revoked access token must now be rejected (401)
    revoked_resp = client.get("/api/auth/me", headers=headers)
    assert revoked_resp.status_code == 401
    print("[PASS] Logout & Session Revocation Verification (401 on Revoked Token)")

def test_edge_cases():
    # 1. Duplicate Username Registration Rejection
    dup_resp = client.post("/api/auth/register", json={
        "username": TEST_USER,
        "email": "unique_email@threatlens.ai",
        "password": TEST_PASSWORD,
        "role": "Security Analyst"
    })
    assert dup_resp.status_code == 400

    # 2. Re-login Analyst to obtain fresh token for upload edge cases
    login_resp = client.post("/api/auth/login", json={"username": TEST_USER, "password": TEST_PASSWORD}).json()
    token = login_resp["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Empty 0-Byte File Upload Rejection
    empty_files = {"file": ("empty.exe", b"", "application/octet-stream")}
    empty_resp = client.post("/api/upload/scan", files=empty_files, headers=headers)
    assert empty_resp.status_code == 400

    # 4. Oversized (>50MB) File Upload Rejection
    oversized_content = b"A" * (50 * 1024 * 1024 + 100)
    over_files = {"file": ("huge_payload.iso", oversized_content, "application/octet-stream")}
    over_resp = client.post("/api/upload/scan", files=over_files, headers=headers)
    assert over_resp.status_code in [400, 413]

    # 5. List Scans History Retrieval
    scans_list_resp = client.get("/api/upload/scans", headers=headers)
    assert scans_list_resp.status_code == 200
    assert scans_list_resp.json()["total_scans"] >= 1

    # 6. Audit Log Action Filtering for Administrator
    admin_headers = {"Authorization": f"Bearer {ADMIN_ACCESS_TOKEN}"}
    audit_filter_resp = client.get("/api/audit/logs?action=LOGIN", headers=admin_headers)
    assert audit_filter_resp.status_code == 200
    filtered_logs = audit_filter_resp.json()["logs"]
    assert all(log["action"] == "LOGIN" for log in filtered_logs)

    print("[PASS] Robustness & Edge-Case Input Rejection Tests (0-Byte, Oversized, Duplicate Auth, Audit Filtering)")

if __name__ == "__main__":
    print("=== Testing ThreatLens AI Backend (Milestones 1 through 4 Evaluation) ===")
    test_health()
    test_register()
    test_login()
    test_refresh_token_rotation()
    test_unauthenticated_access_denied()
    test_file_upload_scan()
    test_async_scan_processing()
    test_sandbox_dynamic_analysis()
    test_rbac_matrix_enforcement()
    test_logout()
    test_edge_cases()
    print("=== ALL MILESTONE 1 - 4 & EDGE CASE TESTS PASSED SUCCESSFULLY! ===")


