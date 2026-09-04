from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.auth.router import router as auth_router
from app.file_upload.router import router as upload_router
from app.audit.router import router as audit_router
from app.database import init_db

app = FastAPI(
    title="ThreatLens AI Backend",
    description="Modular Backend Service for User Authentication, Token Rotation, File Upload Analysis, Sandbox Triggers & Security Audit Logs",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Modular Routers
app.include_router(auth_router)
app.include_router(upload_router)
app.include_router(audit_router)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "ThreatLens AI Backend",
        "review_milestone": "Milestone 1-4 Fully Implemented",
        "docs": "/docs"
    }

@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "database": "sqlite3",
        "milestones": "Milestone 1 through Milestone 4 Complete",
        "modules": [
            "User Authentication & PBKDF2 Password Hashing",
            "Refresh Token Rotation",
            "File Upload & Static EMBER ML Analysis",
            "Asynchronous EMBER Background Pipeline",
            "Sandbox Dynamic Behavioral Triggers",
            "RBAC Role Permission Enforcement",
            "Security Audit Logging Service"
        ]
    }

