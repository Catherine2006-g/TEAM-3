from pydantic import BaseModel
from typing import List, Optional

class AuditLogItem(BaseModel):
    id: int
    username: str
    role: str
    action: str
    resource: str
    details: Optional[str] = ""
    status: str
    timestamp: str

class AuditLogListResponse(BaseModel):
    total_logs: int
    logs: List[AuditLogItem]
