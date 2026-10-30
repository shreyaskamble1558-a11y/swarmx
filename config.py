import os
from pathlib import Path
import secrets


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SWARMX_SECRET_KEY") or secrets.token_hex(32)
    ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.environ.get("SWARMX_COOKIE_SECURE", "").lower() == "true"
    DATABASE = os.environ.get("SWARMX_DATABASE", str(BASE_DIR / "instance" / "swarmx.db"))
    MAX_CONTENT_LENGTH = int(os.environ.get("SWARMX_MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
    MAX_EVENT_COUNT = int(os.environ.get("SWARMX_MAX_EVENT_COUNT", "10000"))
