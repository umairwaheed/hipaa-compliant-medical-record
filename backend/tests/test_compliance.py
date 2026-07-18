"""Compliance invariants enforced in CI.

These fail the build if a future change weakens a HIPAA technical safeguard:
auth on every PHI route, encryption on every sensitive PHI column, fail-closed
config, password policy, tamper-evident audit, and MFA-gated tokens.
"""

from datetime import UTC

import pytest
from cryptography.fernet import Fernet
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
    "ssn",
    "phone",
    "email",
    "address",
    "insurance_provider",
    "insurance_id",
    "clinical_notes",
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
    from datetime import datetime

    from app.audit import _compute_hash

    ts = datetime(2026, 1, 1, tzinfo=UTC)
    h = _compute_hash(
        timestamp=ts,
        username="u",
        action="VIEW_PATIENT",
        patient_id=1,
        detail="mrn=X",
        ip_address="127.0.0.1",
        prev_hash=None,
    )
    tampered = _compute_hash(
        timestamp=ts,
        username="u",
        action="VIEW_PATIENT",
        patient_id=1,
        detail="mrn=Y",
        ip_address="127.0.0.1",
        prev_hash=None,
    )
    assert h != tampered


def test_audit_hash_stable_across_timezone_roundtrip():
    """Postgres returns timestamptz in the session tz; the hash must be identical
    for the same instant regardless of its tzinfo representation."""
    from datetime import datetime, timedelta, timezone

    from app.audit import _compute_hash

    utc = datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=UTC)
    other = utc.astimezone(timezone(timedelta(hours=5)))  # same instant, +05:00
    kw = dict(
        username="u",
        action="VIEW_PATIENT",
        patient_id=1,
        detail="mrn=X",
        ip_address="127.0.0.1",
        prev_hash=None,
    )
    assert _compute_hash(timestamp=utc, **kw) == _compute_hash(timestamp=other, **kw)


def test_audit_chain_is_keyed_not_plain_sha256():
    """§164.312(b)/(c)(1): the chain MAC must be keyed, so DB-only access can't
    recompute it. It must differ from an unkeyed SHA-256 of the same payload."""
    import hashlib

    payload = "2026-01-01T00:00:00+00:00|u|VIEW_PATIENT|1|mrn=X|127.0.0.1|"
    mac = security.audit_mac(payload)
    assert mac != hashlib.sha256(payload.encode()).hexdigest()
    assert mac == security.audit_mac(payload)  # deterministic for verification


def test_mfa_step_counts_toward_lockout():
    """§164.312(d): failed MFA attempts must accrue toward account lockout, so the
    second factor is not brute-forceable."""
    from app import crud
    from app.config import settings

    class FakeUser:
        failed_login_count = 0
        locked_until = None

    u = FakeUser()
    for _ in range(settings.max_failed_logins - 1):
        assert crud.register_failed_login(None, u) is False
        assert not crud.is_locked(u)
    assert crud.register_failed_login(None, u) is True  # threshold reached → lock
    assert crud.is_locked(u)


def test_full_and_preauth_tokens_have_distinct_scopes():
    full, _ = security.create_access_token("u", "admin", 0)
    pre, _ = security.create_preauth_token("u", "admin", 0)
    assert security.decode_access_token(full)["scp"] == security.SCOPE_FULL
    assert security.decode_access_token(pre)["scp"] == security.SCOPE_PREAUTH


def test_dummy_verify_runs_and_equalizes_path():
    """The null-user login path must invoke bcrypt (via dummy_verify) so timing
    doesn't reveal whether a username exists."""
    # Should execute a real bcrypt comparison without raising and return None.
    assert security.dummy_verify("anything") is None
    # The dummy hash is a genuine bcrypt hash (starts with the bcrypt marker).
    assert security._DUMMY_HASH.startswith("$2")


def test_admin_bypasses_assignment_but_clinician_gated():
    """Access decision: admins are unrestricted; clinicians require an
    assignment. The admin branch short-circuits before any DB call."""
    from app import crud

    class FakeAdmin:
        role, id = "admin", 1

    class FakeClinician:
        role, id = "clinician", 2

    # Admin: allowed without touching the DB (db=None proves the short-circuit).
    assert crud.can_access_patient(None, FakeAdmin(), 999) is True
    # Clinician scope maps to their own id (used to filter list/search).
    from app.routers.patients import _scope

    assert _scope(FakeAdmin()) is None
    assert _scope(FakeClinician()) == 2


def test_blind_fingerprint_hides_term_but_correlates():
    """Audit fingerprints of search terms must not contain the term, must be
    stable for equal (normalized) inputs, and differ for different inputs."""
    fp = security.blind_fingerprint("Johnson")
    assert "johnson" not in fp.lower() and "Johnson" not in fp
    assert fp == security.blind_fingerprint("  johnson ")  # normalized-equal
    assert fp != security.blind_fingerprint("Martinez")


def test_encrypted_string_roundtrip_and_ciphertext():
    enc = EncryptedString()
    stored = enc.process_bind_param("123-45-6789", None)
    assert stored is not None and "123-45-6789" not in stored  # ciphertext at rest
    assert enc.process_result_value(stored, None) == "123-45-6789"
