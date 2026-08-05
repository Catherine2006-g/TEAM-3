from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_naive_auth_and_upload():
    # 1. Test Register
    reg_resp = client.post("/api/register", json={
        "username": "naive_dev",
        "email": "naive@threatlens.ai",
        "password": "simplepassword",
        "role": "Security Analyst",
        "full_name": "Naive Developer"
    })
    assert reg_resp.status_code == 200
    print("[PASS] User Registration")

    # 2. Test Login
    login_resp = client.post("/api/login", json={
        "username": "naive_dev",
        "password": "simplepassword"
    })
    assert login_resp.status_code == 200
    print("[PASS] User Login")

    # 3. Test File Upload
    file_payload = b"MZ\x90\x00\x03\x00\x00powershell http://malicious.com"
    upload_resp = client.post("/api/upload", files={"file": ("test.exe", file_payload, "application/octet-stream")})
    assert upload_resp.status_code == 200
    res = upload_resp.json()
    assert "scan_id" in res
    print(f"[PASS] File Upload & Basic Analysis (Risk Score: {res['result']['risk_score']})")

    # 4. Test List Scans
    scans_resp = client.get("/api/scans")
    assert scans_resp.status_code == 200
    assert scans_resp.json()["total_scans"] >= 1
    print("[PASS] List Scans History")

if __name__ == "__main__":
    print("=== Testing Naive 2/10 Auth & Upload Backend ===")
    test_naive_auth_and_upload()
    print("=== ALL TESTS PASSED! ===")
