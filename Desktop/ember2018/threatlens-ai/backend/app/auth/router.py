import uuid
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.auth.schemas import UserRegister, UserLogin, UserProfile, TokenResponse
from app.auth.security import hash_password, verify_password, create_access_token, get_user_from_token, revoke_token
from app.database import get_db

router = APIRouter(prefix="/api/auth", tags=["User Authentication & Role Management"])
security_scheme = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> dict:
    """
    FastAPI Dependency: Extract Bearer token from Authorization header,
    verify validity, and return current authenticated user profile.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing. Header format: 'Authorization: Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = credentials.credentials
    username = get_user_from_token(token)
    
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, full_name FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")
        
    return dict(row)

@router.post("/register")
def register(user_data: UserRegister):
    """Register a new user account with role selection & PBKDF2 password hashing"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Check duplicate username
    cursor.execute("SELECT id FROM users WHERE username = ?", (user_data.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail=f"Username '{user_data.username}' is already taken.")
        
    # Check duplicate email
    cursor.execute("SELECT id FROM users WHERE email = ?", (user_data.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail=f"Email '{user_data.email}' is already registered.")

    # Securely hash password with PBKDF2 + SHA-256
    pwd_hash, salt = hash_password(user_data.password)
    
    cursor.execute(
        "INSERT INTO users (username, email, password, password_hash, salt, role, full_name) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_data.username, user_data.email, "[SECURE_HASH]", pwd_hash, salt, user_data.role, user_data.full_name)
    )
    conn.commit()
    conn.close()
    
    return {
        "status": "success",
        "message": f"User '{user_data.username}' registered successfully.",
        "user": {
            "username": user_data.username,
            "email": user_data.email,
            "role": user_data.role
        }
    }

@router.post("/login")
def login(login_data: UserLogin):
    """Authenticate user credentials and return Bearer access token"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (login_data.username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")
        
    user = dict(row)
    
    # Check password hash
    if user.get("password_hash") and user.get("salt"):
        is_valid = verify_password(login_data.password, user["password_hash"], user["salt"])
    else:
        # Fallback for plain legacy test data
        is_valid = (user.get("password") == login_data.password)
        
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")
        
    token = create_access_token(user["username"])
    
    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user["full_name"]
        }
    }

@router.get("/me")
def profile(current_user: dict = Depends(get_current_user)):
    """Get authenticated profile details of logged in user"""
    return current_user

@router.post("/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    """Revoke current Bearer access token"""
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=400, detail="No authorization token provided.")
        
    revoked = revoke_token(credentials.credentials)
    if not revoked:
        raise HTTPException(status_code=400, detail="Token already invalid or expired.")
        
    return {
        "status": "success",
        "message": "User logged out successfully and token revoked."
    }
