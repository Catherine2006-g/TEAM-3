from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class Hashes(BaseModel):
    md5: str
    sha256: str

class DetectionResult(BaseModel):
    risk_score: int
    verdict: str
    recommended_action: str

class ScanResponse(BaseModel):
    scan_id: str
    filename: str
    file_size: int
    file_type: str
    hashes: Hashes
    static_analysis: Dict[str, Any]
    detection: DetectionResult
    uploaded_by: str
    timestamp: str

class AsyncScanResponse(BaseModel):
    scan_id: str
    filename: str
    status: str
    message: str

class SandboxTriggerResponse(BaseModel):
    scan_id: str
    sandbox_status: str
    dynamic_analysis: Dict[str, Any]

class ScanItemResponse(BaseModel):
    id: str
    filename: str
    file_path: Optional[str] = None
    file_size: int
    file_type: str
    md5: str
    sha256: str
    status: str
    verdict: str
    risk_score: int
    confidence_score: float
    static_analysis: Optional[Dict[str, Any]] = None
    dynamic_analysis: Optional[Dict[str, Any]] = None
    uploaded_by: str
    upload_time: str

class ScanListResponse(BaseModel):
    total_scans: int
    scans: List[ScanItemResponse]

class MessageResponse(BaseModel):
    status: str
    message: str


