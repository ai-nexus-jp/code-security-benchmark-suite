import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
SECRET_DIR = BASE_DIR / "data-secret"

# Create directories if they do not exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
SECRET_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_HOSTS = ["example.com", "api.example.com", "myapp.internal.local"]
DATABASE_URL = f"sqlite:///{BASE_DIR}/app.db"

