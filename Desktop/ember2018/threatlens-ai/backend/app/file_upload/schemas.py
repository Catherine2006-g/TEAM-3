from pydantic import BaseModel
from typing import List, Dict, Any

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
