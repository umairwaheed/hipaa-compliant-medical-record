"""Application configuration.

Fail-closed: the application refuses to start unless the security-critical
secrets are supplied. There are NO insecure defaults for the encryption key,
JWT secret, or database URL — a missing value is a hard error, not a silent
fallback. Secrets are injected via the environment / a root-owned `.env` that is
never committed.
"""
from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Required secrets (no defaults; boot fails if unset) ---
    secret_key: str = Field(min_length=32)
    database_url: str

    # --- PHI key source ---
    # "env"   → the Fernet key is PHI_ENCRYPTION_KEY (required).
    # "vault" → the key is unwrapped at boot from Vault transit (KMS), so the
    #           plaintext key never lives in config. See app/keyprovider.py.
    key_provider: str = "env"
    phi_encryption_key: str | None = None  # required only when key_provider="env"

    # Vault (used only when key_provider="vault")
    vault_addr: str | None = None
    vault_role_id: str | None = None
    vault_secret_id: str | None = None
    vault_cacert: str | None = None          # path to Vault's CA/cert for TLS verify
    vault_transit_key: str = "hipaa-phi"
    wrapped_phi_dek: str | None = None       # transit ciphertext of the DEK

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
    def _reject_placeholders(cls, v: str | None) -> str | None:
        if v is None:
            return v
        lowered = v.lower()
        if any(bad in lowered for bad in ("changeme", "change-me", "insecure", "dev-only", "placeholder")):
            raise ValueError("Refusing to boot with a placeholder secret. Provide a real value.")
        return v

    @model_validator(mode="after")
    def _validate_key_provider(self):
        if self.key_provider == "env":
            if not self.phi_encryption_key or len(self.phi_encryption_key) < 32:
                raise ValueError("PHI_ENCRYPTION_KEY is required (>=32 chars) when KEY_PROVIDER=env.")
        elif self.key_provider == "vault":
            missing = [
                name for name, val in [
                    ("VAULT_ADDR", self.vault_addr),
                    ("VAULT_ROLE_ID", self.vault_role_id),
                    ("VAULT_SECRET_ID", self.vault_secret_id),
                    ("WRAPPED_PHI_DEK", self.wrapped_phi_dek),
                ] if not val
            ]
            if missing:
                raise ValueError(f"KEY_PROVIDER=vault requires: {', '.join(missing)}")
        else:
            raise ValueError("KEY_PROVIDER must be 'env' or 'vault'.")
        return self

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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
