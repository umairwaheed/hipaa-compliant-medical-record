"""Compliance invariants enforced in CI.

These fail the build if a future change weakens a HIPAA technical safeguard:
auth on every PHI route, encryption on every sensitive PHI column, fail-closed
config, password policy, tamper-evident audit, and MFA-gated tokens.
"""
import pytest
from cryptography.fernet import Fernet
from fastapi import Depends
from pydantic import ValidationError

from app import security
from app.config import Settings
from app.deps import get_current_user, require_admin
from app.models import Patient
from app.routers import audit as audit_router
from app.routers import patients as patients_router
from app.routers import users as users_router
from app.security import EncryptedString

# Auth dependencies that gate PHI access.
_AUTH_DEPS = {get_current_user, require_admin}

# Patient columns that must be encrypted at rest.
_MUST_ENCRYPT = {
    "ssn", "phone", "email", "address",
    "insurance_provider", "insurance_id", "clinical_notes",
}


def _route_dependencies(route):
    """Collect the dependency callables declared on a route."""
    deps = set()
    for dep in route.dependant.dependencies:
        if dep.call is not None:
            deps.add(dep.call)
    return deps


@pytest.mark.parametrize(
    "router", [patients_router.router, audit_router.router, users_router.router]
)
def test_every_route_requires_authentication(router):
    """§164.312(a) Access Control — no PHI route is reachable unauthenticated."""
    for route in router.routes:
        deps = _route_dependencies(route)
        assert deps & _AUTH_DEPS, f"Route {route.path} is missing an auth dependency"


def test_sensitive_patient_columns_are_encrypted():
    """§164.312(a)(2)(iv) — sensitive PHI columns use EncryptedString."""
    for name in _MUST_ENCRYPT:
        col = Patient.__table__.c[name]
        assert isinstance(col.type, EncryptedString), f"{name} is not encrypted at rest"


def test_config_fails_closed_on_placeholder_secret():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            secret_key="dev-only-insecure-secret-change-me",
            phi_encryption_key=Fernet.generate_key().decode(),
            database_url="postgresql+psycopg://u:p@localhost/db",
            cors_origins="https://x.test",
        )


def test_config_rejects_non_postgres():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            secret_key="a-perfectly-fine-secret-value-abcdefgh",
            phi_encryption_key=Fernet.generate_key().decode(),
            database_url="sqlite:///./x.db",
            cors_origins="https://x.test",
        )


@pytest.mark.parametrize("weak", ["short", "alllowercase123", "NoDigits!!", "nnnnnnnnnnnn"])
def test_password_policy_rejects_weak(weak):
    with pytest.raises(security.PasswordPolicyError):
        security.validate_password_policy(weak)


def test_password_policy_accepts_strong():
    security.validate_password_policy("Str0ng-P@ssw0rd!")


def test_audit_hash_detects_tampering():
    """A modified detail must not recompute to the stored hash."""
    from app.audit import _compute_hash
    from datetime import datetime, timezone

    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    h = _compute_hash(timestamp=ts, username="u", action="VIEW_PATIENT",
                      patient_id=1, detail="mrn=X", ip_address="127.0.0.1", prev_hash=None)
    tampered = _compute_hash(timestamp=ts, username="u", action="VIEW_PATIENT",
                             patient_id=1, detail="mrn=Y", ip_address="127.0.0.1", prev_hash=None)
    assert h != tampered


def test_audit_hash_stable_across_timezone_roundtrip():
    """Postgres returns timestamptz in the session tz; the hash must be identical
    for the same instant regardless of its tzinfo representation."""
    from app.audit import _compute_hash
    from datetime import datetime, timezone, timedelta

    utc = datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
    other = utc.astimezone(timezone(timedelta(hours=5)))  # same instant, +05:00
    kw = dict(username="u", action="VIEW_PATIENT", patient_id=1,
              detail="mrn=X", ip_address="127.0.0.1", prev_hash=None)
    assert _compute_hash(timestamp=utc, **kw) == _compute_hash(timestamp=other, **kw)


def test_full_and_preauth_tokens_have_distinct_scopes():
    full, _ = security.create_access_token("u", "admin", 0)
    pre, _ = security.create_preauth_token("u", "admin", 0)
    assert security.decode_access_token(full)["scp"] == security.SCOPE_FULL
    assert security.decode_access_token(pre)["scp"] == security.SCOPE_PREAUTH


def test_encrypted_string_roundtrip_and_ciphertext():
    enc = EncryptedString()
    stored = enc.process_bind_param("123-45-6789", None)
    assert stored is not None and "123-45-6789" not in stored  # ciphertext at rest
    assert enc.process_result_value(stored, None) == "123-45-6789"
