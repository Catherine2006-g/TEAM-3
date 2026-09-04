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

def create_refresh_token(username: str) -> str:
    """
    Generate a secure refresh token and persist in refresh_tokens database table.
    """
    from app.database import get_db
    import datetime
    
    refresh_token = f"tl_ref_{uuid.uuid4().hex}"
    now = datetime.datetime.now()
    expires_at = (now + datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO refresh_tokens (token, username, expires_at, revoked, created_at) VALUES (?, ?, ?, 0, ?)",
        (refresh_token, username, expires_at, created_at)
    )
    conn.commit()
    conn.close()
    
    return refresh_token

def rotate_refresh_token(refresh_token: str) -> Tuple[str, str, str]:
    """
    Milestone 3 Refresh Token Rotation:
    Validates provided refresh_token, marks it as revoked, and issues a new access_token + new refresh_token.
    Returns (username, new_access_token, new_refresh_token) or (None, None, None) if invalid.
    """
    from app.database import get_db
    import datetime
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, expires_at, revoked FROM refresh_tokens WHERE token = ?", (refresh_token,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return None, None, None
        
    username, expires_at_str, revoked = row["username"], row["expires_at"], row["revoked"]
    
    if revoked == 1:
        conn.close()
        return None, None, None
        
    # Check expiration
    expires_at = datetime.datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
    if datetime.datetime.now() > expires_at:
        cursor.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (refresh_token,))
        conn.commit()
        conn.close()
        return None, None, None
        
    # Revoke used refresh token (Rotation)
    cursor.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (refresh_token,))
    conn.commit()
    conn.close()
    
    # Issue fresh tokens
    new_access_token = create_access_token(username)
    new_refresh_token = create_refresh_token(username)
    
    return username, new_access_token, new_refresh_token

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

