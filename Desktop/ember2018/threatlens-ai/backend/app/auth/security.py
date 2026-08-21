import os
import hashlib
import hmac
import uuid
from typing import Tuple, Dict

# In-memory session token store (for Milestone 2 token authorization)
# Maps access_token -> username
ACTIVE_TOKENS: Dict[str, str] = {}

def hash_password(password: str) -> Tuple[str, str]:
    """
    Hash a password using PBKDF2 HMAC SHA-256 with a random salt.
    Returns (hashed_password_hex, salt_hex)
    """
    salt = os.urandom(16)
    salt_hex = salt.hex()
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    ).hex()
    return pwd_hash, salt_hex

def verify_password(plain_password: str, hashed_password: str, salt_hex: str) -> bool:
    """
    Verify a plain password against stored PBKDF2 hash and salt.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt,
            100000
        ).hex()
        return hmac.compare_digest(pwd_hash, hashed_password)
    except Exception:
        return False

def create_access_token(username: str) -> str:
    """
    Generate a secure random Bearer token and store in active session table.
    """
    token = f"tl_sec_{uuid.uuid4().hex}"
    ACTIVE_TOKENS[token] = username
    return token

def get_user_from_token(token: str) -> str:
    """
    Retrieve username associated with active token. Returns None if invalid.
    """
    return ACTIVE_TOKENS.get(token)

def revoke_token(token: str) -> bool:
    """
    Revoke/invalidate an active access token on logout.
    """
    if token in ACTIVE_TOKENS:
        del ACTIVE_TOKENS[token]
        return True
    return False
