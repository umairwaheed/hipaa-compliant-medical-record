"""Application configuration.

Fail-closed: the application refuses to start unless the security-critical
secrets are supplied. There are NO insecure defaults for the encryption key,
JWT secret, or database URL — a missing value is a hard error, not a silent
fallback. Secrets are injected via the environment / a root-owned `.env` that is
never committed.
"""
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Required secrets (no defaults; boot fails if unset) ---
    secret_key: str = Field(min_length=32)
    phi_encryption_key: str = Field(min_length=32)
    database_url: str

    # --- Environment ---
    environment: str = "production"  # production | staging
    cors_origins: str  # required, comma-separated; no wildcard in production

    # --- Auth / session policy ---
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15          # automatic logoff
    preauth_token_expire_minutes: int = 5          # MFA challenge window
    mfa_issuer: str = "HIPAA Medical Records"

    # --- Account lockout ---
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # --- Password policy ---
    min_password_length: int = 12

    @field_validator("secret_key", "phi_encryption_key")
    @classmethod
    def _reject_placeholders(cls, v: str) -> str:
        lowered = v.lower()
        if any(bad in lowered for bad in ("changeme", "change-me", "insecure", "dev-only", "placeholder")):
            raise ValueError("Refusing to boot with a placeholder secret. Provide a real value.")
        return v

    @field_validator("database_url")
    @classmethod
    def _require_postgres(cls, v: str) -> str:
        if not v.startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("DATABASE_URL must be a PostgreSQL URL (postgresql+psycopg://...).")
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        if self.environment == "production" and "*" in origins:
            raise ValueError("Wildcard CORS origin is not permitted in production.")
        return origins

    @property
    def fernet_key(self) -> bytes:
        return self.phi_encryption_key.encode()


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
