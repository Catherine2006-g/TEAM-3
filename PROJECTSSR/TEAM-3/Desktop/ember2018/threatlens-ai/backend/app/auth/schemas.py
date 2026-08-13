from pydantic import BaseModel
from typing import Optional

class UserRegister(BaseModel):
    username: str
    email: str
    password: str
    role: str = "Security Analyst"  # Security Analyst, SOC Team Member, Administrator, Researcher
    full_name: Optional[str] = ""

class UserLogin(BaseModel):
    username: str
    password: str

class UserProfile(BaseModel):
    id: Optional[int] = None
    username: str
    email: str
    role: str
    full_name: Optional[str] = ""
