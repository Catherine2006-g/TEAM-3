import datetime
from app.database import get_db

def log_audit_event(
    username: str,
    role: str,
    action: str,
    resource: str,
    details: str = "",
    status: str = "SUCCESS"
):
    """
    Persist security audit event to the database audit_logs table.
    """
    try:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (username, role, action, resource, details, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (username, role, action, resource, details, status, now_str)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDIT LOG ERROR] Failed to record audit log: {e}")
