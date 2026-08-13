import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Storage Paths
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = BASE_DIR / "database.db"
