import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.schemas import UserRegister, UserLogin, UserProfile
from app.database import get_db
from app.models import User


router = APIRouter(
    prefix="/api/auth",
    tags=["User Authentication & Role Management"]
)


@router.post("/register")
def register(
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    """Register a new user account with role selection."""

    # Check whether username already exists
    existing_user = (
        db.query(User)
        .filter(User.username == user_data.username)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{user_data.username}' is already taken."
        )

    # Check whether email already exists
    existing_email = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email '{user_data.email}' is already registered."
        )

    # Create new user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        role=user_data.role,
        full_name=user_data.full_name
    )

    # Add user to PostgreSQL session
    db.add(new_user)

    try:
        db.commit()
        db.refresh(new_user)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create user."
        )

    return {
        "status": "success",
        "message": f"User '{new_user.username}' registered successfully.",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "role": new_user.role,
            "full_name": new_user.full_name
        }
    }


@router.post("/login")
def login(
    login_data: UserLogin,
    db: Session = Depends(get_db)
):
    """Authenticate user and return access token."""

    user = (
        db.query(User)
        .filter(
            User.username == login_data.username,
            User.password == login_data.password
        )
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )

    # Temporary token generation used by the existing project
    token = f"token_{user.username}_{uuid.uuid4().hex[:8]}"

    return {
        "status": "success",
        "access_token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "full_name": user.full_name
        }
    }


@router.get("/me")
def profile(
    username: str = "analyst_demo",
    db: Session = Depends(get_db)
):
    """Get profile details of the logged-in user."""

    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if not user:
        return {
            "id": 1,
            "username": username,
            "email": f"{username}@threatlens.ai",
            "role": "Security Analyst",
            "full_name": "Demo Security Analyst"
        }

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "full_name": user.full_name
    }