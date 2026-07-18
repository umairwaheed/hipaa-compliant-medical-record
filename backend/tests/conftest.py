"""Test fixtures. Sets fail-closed-satisfying secrets in the environment BEFORE
the app is imported so modules load offline (create_engine does not connect)."""
import os

from cryptography.fernet import Fernet

os.environ.setdefault("SECRET_KEY", "test-secret-" + "x" * 40)
os.environ.setdefault("PHI_ENCRYPTION_KEY", Fernet.generate_key().decode())
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://u:p@127.0.0.1:5432/none")
os.environ.setdefault("CORS_ORIGINS", "https://example.test")
os.environ.setdefault("ENVIRONMENT", "staging")
