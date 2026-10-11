import os
import secrets
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the application
BASE_DIR = Path(__file__).resolve().parent

# Load .env file if it exists
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration with secure defaults."""

    # Secret key for session signing and cryptographic operations
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY or SECRET_KEY.startswith("replace_with"):
        # In development/test mode, auto-generate an ephemeral secure random key with notice
        SECRET_KEY = secrets.token_hex(32)

    # Environment
    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    TESTING = False

    # Database
    DATABASE_PATH = os.getenv(
        "DATABASE_PATH", str(BASE_DIR / "instance" / "secure_auth.sqlite3")
    )

    # Session Cookie Security
    # In production over HTTPS, SESSION_COOKIE_SECURE must be True
    SESSION_COOKIE_SECURE = (
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    )
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.getenv("PERMANENT_SESSION_LIFETIME_MINUTES", "30"))
    )

    # Rate Limiting & Account Lockout
    MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))
    IP_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("IP_RATE_LIMIT_WINDOW_SECONDS", "300"))
    IP_RATE_LIMIT_MAX_REQUESTS = int(os.getenv("IP_RATE_LIMIT_MAX_REQUESTS", "20"))

    # Password Reset
    RESET_TOKEN_EXPIRY_MINUTES = int(os.getenv("RESET_TOKEN_EXPIRY_MINUTES", "15"))
    DEV_EMAIL_SIMULATOR = (
        os.getenv("DEV_EMAIL_SIMULATOR", "true").lower() == "true"
    )


class TestConfig(Config):
    """Test configuration using in-memory or isolated test database."""

    TESTING = True
    DEBUG = False
    SECRET_KEY = "test_super_secret_cryptographic_key_32_bytes_min!"
    DATABASE_PATH = ":memory:"
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = True
    MAX_FAILED_LOGIN_ATTEMPTS = 3
    LOCKOUT_DURATION_MINUTES = 5
    IP_RATE_LIMIT_MAX_REQUESTS = 10
    RESET_TOKEN_EXPIRY_MINUTES = 10
