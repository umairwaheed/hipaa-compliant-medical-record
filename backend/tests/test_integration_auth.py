"""Endpoint integration tests against a real PostgreSQL (the audit chain uses
Postgres advisory locks, so SQLite won't do). Skipped unless TEST_DATABASE_URL
is set — CI provides a postgres service.

The headline test reproduces the shared-counter MFA-lockout bug: an attacker who
holds the password must NOT be able to keep the account under the lockout
threshold by re-logging-in (which used to reset the counter) between TOTP
guesses. These requests hit the ASGI app directly, so nginx rate-limiting is not
in play — this asserts the *application-level* lockout specifically.
"""
import os

import pytest

TEST_DB = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_DB, reason="set TEST_DATABASE_URL to run integration tests")

if TEST_DB:
    import pyotp
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app import models, security
    from app.database import Base, get_db
    from app.main import app

    engine = create_engine(TEST_DB)
    TestSession = sessionmaker(bind=engine, autoflush=False)

    def _override_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_db
    client = TestClient(app)


@pytest.fixture(autouse=True)
def _fresh_schema():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


def _create_user(username: str, password: str) -> None:
    db = TestSession()
    db.add(models.User(username=username, full_name="Test User",
                       hashed_password=security.hash_password(password), role="clinician"))
    db.commit()
    db.close()


def _login(username: str, password: str):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def _enroll_mfa(username: str, password: str) -> str:
    pre = _login(username, password).json()["preauth_token"]
    secret = client.post("/api/auth/mfa/enroll", headers={"Authorization": f"Bearer {pre}"}).json()["secret"]
    r = client.post("/api/auth/mfa/enroll/verify", json={"code": pyotp.TOTP(secret).now()},
                    headers={"Authorization": f"Bearer {pre}"})
    assert r.status_code == 200
    return secret


def test_mfa_locks_out_despite_interleaved_password_logins():
    _create_user("bruteme", "Password-1234!")
    _enroll_mfa("bruteme", "Password-1234!")

    locked = False
    for _ in range(8):
        r = _login("bruteme", "Password-1234!")          # fresh password login each round
        if r.status_code == 423:                          # locked at the password step
            locked = True
            break
        pre = r.json()["preauth_token"]
        v = client.post("/api/auth/mfa/verify", json={"code": "000000"},
                        headers={"Authorization": f"Bearer {pre}"})
        if v.status_code == 423:
            locked = True
            break
    assert locked, "MFA lockout must trigger despite interleaved password logins"


def test_successful_mfa_resets_counter_for_legit_user():
    secret = (_create_user("gooduser", "Password-1234!"), _enroll_mfa("gooduser", "Password-1234!"))[1]
    pre = _login("gooduser", "Password-1234!").json()["preauth_token"]
    # a couple of typos, then the right code — must succeed (not locked)
    for _ in range(2):
        client.post("/api/auth/mfa/verify", json={"code": "000000"}, headers={"Authorization": f"Bearer {pre}"})
    good = client.post("/api/auth/mfa/verify", json={"code": pyotp.TOTP(secret).now()},
                       headers={"Authorization": f"Bearer {pre}"})
    assert good.status_code == 200
