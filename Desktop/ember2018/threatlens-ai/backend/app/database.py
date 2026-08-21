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
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Security Analyst',
            full_name TEXT
        )
    ''')
    
    # 2. File Scans Table (File Upload & Static Analysis)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_scans (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_type TEXT NOT NULL,
            md5 TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            uploaded_by TEXT NOT NULL,
            upload_time TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize tables
init_db()
