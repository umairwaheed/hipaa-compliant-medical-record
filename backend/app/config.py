"""Application configuration.

Secrets are read from the environment (12-factor). A `.env` file is loaded for
local development only; production deployments should inject real secrets through
the platform's secret manager, never a committed file.
"""
from functools import lru_cache

from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Auth
    secret_key: str = "dev-only-insecure-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15  # HIPAA automatic logoff

    # PHI encryption at rest. If unset in dev we derive an ephemeral key so the
    # app boots, but the DB then cannot be decrypted across restarts — a loud
    # signal that a real key must be configured.
    phi_encryption_key: str = ""

    # Infra
    database_url: str = "sqlite:///./hipaa_demo.db"
    cors_origins: str = "http://localhost:5173"

    # Seeded demo accounts (demo only — never seed default creds in production).
    seed_admin_username: str = "admin"
    seed_admin_password: str = "Admin123!"
    seed_clinician_username: str = "dr.smith"
    seed_clinician_password: str = "Clinician123!"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def fernet_key(self) -> bytes:
        if self.phi_encryption_key:
            return self.phi_encryption_key.encode()
        # Ephemeral fallback for first-run dev convenience only.
        return Fernet.generate_key()


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
