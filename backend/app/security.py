"""Cryptographic building blocks for the HIPAA technical safeguards.

- Password hashing (bcrypt) for stored credentials.
- JWT issuance/verification for authentication + automatic logoff.
- A SQLAlchemy `EncryptedString` type that transparently encrypts PHI columns
  at rest with Fernet (AES-128-CBC + HMAC authentication).
"""
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String, TypeDecorator

from .config import settings

_fernet = Fernet(settings.fernet_key)


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# JWT access tokens
# --------------------------------------------------------------------------- #
def create_access_token(subject: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "role": role, "iat": now, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.PyJWTError (incl. ExpiredSignatureError) on any problem."""
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


# --------------------------------------------------------------------------- #
# PHI encryption at rest
# --------------------------------------------------------------------------- #
class EncryptedString(TypeDecorator):
    """Encrypts a string value before it is written to the database and decrypts
    it on read. Used for the most sensitive PHI (SSN, contact info, clinical
    notes). Ciphertext is what actually lands in SQLite, so a stolen DB file
    yields no readable PHI without the Fernet key.

    Trade-off: encrypted columns are opaque to SQL `LIKE`/`=`, so they cannot be
    searched directly. A production system needing search over these would add a
    blind index (HMAC of a normalized value). See README.
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        return _fernet.encrypt(value.encode()).decode()

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        try:
            return _fernet.decrypt(value.encode()).decode()
        except InvalidToken:
            # Wrong/rotated key — never silently return ciphertext as if it were PHI.
            return "<decryption-error>"
