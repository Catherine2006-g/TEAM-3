import uuid
from fastapi import APIRouter, HTTPException, status
from app.auth.schemas import UserRegister, UserLogin, UserProfile
from app.database import get_db

router = APIRouter(prefix="/api/auth", tags=["User Authentication & Role Management"])

@router.post("/register")
def register(user_data: UserRegister):
    """Register a new user account with role selection"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Check duplicate username
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_data.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail=f"Username '{user_data.username}' is already taken.")
        
    cursor.execute(
        "INSERT INTO users (username, email, password, role, full_name) VALUES (?, ?, ?, ?, ?)",
        (user_data.username, user_data.email, user_data.password, user_data.role, user_data.full_name)
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
    """Authenticate user and return access token"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (login_data.username, login_data.password)
    )
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")
        
    user = dict(row)
    token = f"token_{user['username']}_{uuid.uuid4().hex[:8]}"
    
    return {
        "status": "success",
        "access_token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user["full_name"]
        }
    }

@router.get("/me")
def profile(username: str = "analyst_demo"):
    """Get profile details of logged in user"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, full_name FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return {
            "id": 1,
            "username": username,
            "email": f"{username}@threatlens.ai",
            "role": "Security Analyst",
            "full_name": "Demo Security Analyst"
        }
        
    return dict(row)
