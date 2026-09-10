from pydantic import BaseModel, Field
from typing import Optional

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, description="Username must be at least 3 characters")
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")
    role: str = Field("Security Analyst", description="Role: Security Analyst, SOC Team Member, Administrator, Researcher")
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

class UserRegisterResponse(BaseModel):
    status: str
    message: str
    user: dict

class TokenResponse(BaseModel):
    status: str
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: UserProfile

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class MessageResponse(BaseModel):
    status: str
    message: str


