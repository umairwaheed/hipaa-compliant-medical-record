"""Cryptographic building blocks for the HIPAA technical safeguards.

- Password hashing (bcrypt) + password-policy enforcement.
- JWT issuance/verification with scopes, per-token ``jti``, and a per-user
  ``token_version`` for global session revocation.
- TOTP (RFC 6238) multi-factor authentication helpers.
- A SQLAlchemy ``EncryptedString`` type that transparently encrypts PHI columns
  at rest with Fernet (AES-128-CBC + HMAC authentication).

The PHI key comes from ``keyprovider.load_phi_key()`` (env or Vault), which fails
closed, so the module cannot be imported without a usable key.
"""
import base64
import hashlib
import hmac
import io
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String, TypeDecorator

from .config import settings
from .keyprovider import load_phi_key

_fernet = Fernet(load_phi_key())

# JWT scopes
SCOPE_FULL = "full"        # normal authenticated access to PHI
SCOPE_PREAUTH = "preauth"  # password verified, MFA step still pending


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
# bcrypt hashes at most 72 bytes; enforce an upper bound so longer passwords are
# not silently truncated.
_MAX_PASSWORD_BYTES = 72


class PasswordPolicyError(ValueError):
    pass


def validate_password_policy(password: str) -> None:
    if len(password) < settings.min_password_length:
        raise PasswordPolicyError(
            f"Password must be at least {settings.min_password_length} characters."
        )
    if len(password.encode()) > _MAX_PASSWORD_BYTES:
        raise PasswordPolicyError("Password is too long (max 72 bytes).")
    checks = [
        (r"[a-z]", "a lowercase letter"),
        (r"[A-Z]", "an uppercase letter"),
        (r"\d", "a digit"),
        (r"[^A-Za-z0-9]", "a symbol"),
    ]
    missing = [desc for pattern, desc in checks if not re.search(pattern, password)]
    if missing:
        raise PasswordPolicyError("Password must contain " + ", ".join(missing) + ".")


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode()[:_MAX_PASSWORD_BYTES], bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode()[:_MAX_PASSWORD_BYTES], hashed.encode())
    except ValueError:
        return False


# Precomputed hash of a throwaway value. When a login is attempted for a
# non-existent user we still run a bcrypt comparison against this hash so the
# response time matches the wrong-password path — closing the username-
# enumeration timing side channel (feeds §164.312(d)).
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt()).decode()


def dummy_verify(plain: str = "") -> None:
    verify_password(plain or "x", _DUMMY_HASH)


def blind_fingerprint(value: str) -> str:
    """Keyed, non-reversible fingerprint of a (possibly PHI) value. Identical
    inputs map to the same fingerprint (useful for audit correlation) but the
    original cannot be recovered without the key — so PHI such as a searched
    patient name never lands in the audit log in plaintext."""
    normalized = value.strip().lower().encode()
    return hmac.new(settings.secret_key.encode(), normalized, hashlib.sha256).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# JWT access tokens
# --------------------------------------------------------------------------- #
def _encode(subject: str, role: str, scope: str, token_version: int, minutes: int) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    jti = uuid.uuid4().hex
    payload = {
        "sub": subject,
        "role": role,
        "scp": scope,
        "ver": token_version,
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm), jti


def create_access_token(subject: str, role: str, token_version: int) -> tuple[str, str]:
    return _encode(subject, role, SCOPE_FULL, token_version, settings.access_token_expire_minutes)


def create_preauth_token(subject: str, role: str, token_version: int) -> tuple[str, str]:
    return _encode(subject, role, SCOPE_PREAUTH, token_version, settings.preauth_token_expire_minutes)


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.PyJWTError (incl. ExpiredSignatureError) on any problem."""
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


# --------------------------------------------------------------------------- #
# TOTP multi-factor authentication
# --------------------------------------------------------------------------- #
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account_name: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=settings.mfa_issuer)


def totp_qr_data_uri(provisioning_uri: str) -> str:
    """Render the otpauth URI as a base64 PNG data URI (no external QR service)."""
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def verify_totp(secret: str, code: str) -> bool:
    # valid_window=1 tolerates ~30s clock drift on either side.
    return pyotp.TOTP(secret).verify((code or "").strip(), valid_window=1)


# --------------------------------------------------------------------------- #
# PHI encryption at rest
# --------------------------------------------------------------------------- #
class EncryptedString(TypeDecorator):
    """Encrypts a string before it is written to the database and decrypts it on
    read. Used for the most sensitive PHI (SSN, contact info, insurance, clinical
    notes) and for stored TOTP secrets. Ciphertext is what lands in Postgres, so
    a stolen database yields no readable PHI without the Fernet key.

    Trade-off: encrypted columns are opaque to SQL ``LIKE``/``=`` and cannot be
    searched directly. Searchable identifiers (name, MRN, DOB) are stored in
    plaintext and protected by the access-control + audit layers; a blind index
    would be the production path to searching encrypted values.
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
            # Wrong/rotated key — fail closed; never surface ciphertext as PHI.
            return "<decryption-error>"
