import sqlite3
from app.config import DB_PATH

def get_db():
    """Get SQLite database connection"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables for User Auth and File Uploads"""
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Users Table (Authentication & Role Management)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            password_hash TEXT,
            salt TEXT,
            role TEXT NOT NULL DEFAULT 'Security Analyst',
            full_name TEXT
        )
    ''')
    
    # Check if existing database needs schema migration for password_hash and salt
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    if "password_hash" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    if "salt" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN salt TEXT")
    
    # 2. Refresh Tokens Table (Milestone 3 Token Rotation)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')

    # 3. File Scans Table (File Upload, Static/Dynamic Analysis & Async Pipeline)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_scans (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_path TEXT,
            file_size INTEGER NOT NULL,
            file_type TEXT NOT NULL,
            md5 TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'COMPLETED',
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            confidence_score REAL DEFAULT 0.0,
            static_analysis_json TEXT,
            dynamic_analysis_json TEXT,
            uploaded_by TEXT NOT NULL,
            upload_time TEXT NOT NULL
        )
    ''')
    
    # Check if existing database needs schema migration for file_scans columns
    cursor.execute("PRAGMA table_info(file_scans)")
    scan_cols = [row[1] for row in cursor.fetchall()]
    if "file_path" not in scan_cols:
        cursor.execute("ALTER TABLE file_scans ADD COLUMN file_path TEXT")
    if "status" not in scan_cols:
        cursor.execute("ALTER TABLE file_scans ADD COLUMN status TEXT DEFAULT 'COMPLETED'")
    if "confidence_score" not in scan_cols:
        cursor.execute("ALTER TABLE file_scans ADD COLUMN confidence_score REAL DEFAULT 0.0")
    if "static_analysis_json" not in scan_cols:
        cursor.execute("ALTER TABLE file_scans ADD COLUMN static_analysis_json TEXT")
    if "dynamic_analysis_json" not in scan_cols:
        cursor.execute("ALTER TABLE file_scans ADD COLUMN dynamic_analysis_json TEXT")

    # 4. Audit Logs Table (Milestone 4 Governance & Security Audit Trail)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            details TEXT,
            status TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize tables
init_db()

