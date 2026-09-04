from fastapi import APIRouter, Depends, HTTPException, status
from app.auth.router import get_current_user
from app.database import get_db

router = APIRouter(prefix="/api/audit", tags=["Audit & Security Logs"])

@router.get("/logs")
def get_audit_logs(
    limit: int = 100,
    action: str = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Retrieve security audit logs (Restricted to Administrator role - Milestone 4 RBAC)
    """
    if current_user.get("role") != "Administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Only Administrator role is authorized to inspect security audit logs."
        )
        
    conn = get_db()
    cursor = conn.cursor()
    if action:
        cursor.execute("SELECT * FROM audit_logs WHERE action = ? ORDER BY timestamp DESC LIMIT ?", (action, limit))
    else:
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        
    rows = cursor.fetchall()
    conn.close()
    
    return {
        "total_logs": len(rows),
        "logs": [dict(r) for r in rows]
    }
