# HIPAA Medical Record Manager

An electronic health record (EHR) system implementing the **HIPAA Security Rule
technical safeguards** (45 CFR §164.312). **FastAPI + SQLAlchemy + PostgreSQL**
backend, **React (Vite)** frontend.

> **Scope of this repository.** It implements and verifies the *technical*
> safeguards. Full HIPAA compliance for real PHI additionally requires the
> administrative and physical safeguards, a documented risk assessment, Business
> Associate Agreements, and BAA-covered infrastructure — the responsibility of
> the operating organization. See [`COMPLIANCE.md`](COMPLIANCE.md).

## Features

- Create, view, edit, and search patient records
- Mandatory multi-factor authentication (TOTP) with role-based access
- Every access to PHI recorded in a tamper-evident, hash-chained audit trail
- Sensitive PHI encrypted at rest; fail-closed configuration

## HIPAA technical safeguards

| Safeguard (45 CFR §164.312) | Implementation |
|---|---|
| **Access Control** §164.312(a)(1) | Per-user accounts; every API route requires a valid full-session JWT; RBAC gates the audit log. `app/deps.py` |
| **Automatic Logoff** §164.312(a)(2)(iii) | Short-lived JWTs (15 min); SPA clears session and redirects on 401. Server-side revocation (logout + token-version bump). `app/security.py`, `app/deps.py` |
| **Encryption at rest** §164.312(a)(2)(iv) | `EncryptedString` encrypts SSN, contact, insurance, notes, and TOTP secrets with Fernet before they reach Postgres. `app/security.py` |
| **Audit Controls** §164.312(b) | Append-only, **hash-chained** `AuditLog` — every login, MFA event, search, view, create, and update. Chain verifiable via `/api/audit/verify` or the CLI. `app/audit.py` |
| **Integrity** §164.312(c)(1) | Updates record which fields changed; Fernet HMAC + the audit hash chain detect tampering. |
| **Person/Entity Authentication** §164.312(d) | bcrypt passwords + password policy; **mandatory TOTP MFA**; account lockout on repeated failures. `app/routers/auth.py` |
| **Transmission Security** §164.312(e) | nginx TLS + HSTS at the edge; app sets `no-store`, `nosniff`, strict CSP, `X-Frame-Options: DENY`. `deploy/nginx-hipaa.conf`, `app/main.py` |
| **Minimum Necessary** (Privacy Rule) | List/search return a reduced projection (no SSN/notes); full PHI only on an audited single-record view. |

Additional hardening: fail-closed secrets (app refuses to boot without a real
encryption key / JWT secret / Postgres URL), login rate-limiting at nginx, no
default credentials, no interactive API docs in production.

## Architecture

```
backend/                 FastAPI service
  app/
    config.py            Fail-closed settings & secrets
    database.py          SQLAlchemy engine/session (PostgreSQL)
    security.py          Passwords, JWT+scopes, TOTP, PHI encryption
    models.py            User, Patient, AuditLog, TokenBlocklist
    schemas.py           Pydantic models
    crud.py              Data-access layer (+ lockout, revocation)
    audit.py             Hash-chained audit writer + chain verifier
    deps.py              Auth + RBAC dependencies
    cli.py               create-admin / reset-password / verify-audit
    routers/             auth (MFA flow), patients, audit
    main.py              App wiring, security headers, CORS
  alembic/               Database migrations
  tests/                 Compliance test suite (CI-enforced)
frontend/                React (Vite) SPA — MFA enrollment + login, records UI
deploy/                  systemd units, nginx vhost, encrypted backup job
```

## Running

This is deployed as a systemd-managed service behind nginx. See
[`DEPLOY.md`](DEPLOY.md) for full production setup. Quick local backend run
against a Postgres instance:

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # set SECRET_KEY, PHI_ENCRYPTION_KEY, DATABASE_URL, CORS_ORIGINS
alembic upgrade head
python -m app.cli create-admin --username admin --full-name "Site Admin"
gunicorn app.main:app -k uvicorn.workers.UvicornWorker -b 127.0.0.1:8000
```

Frontend:

```bash
cd frontend && npm ci && npm run build   # or `npm run dev` for local development
```

## Tests

The compliance suite asserts the safeguards can't silently regress — auth on
every PHI route, encryption on every sensitive column, fail-closed config,
password policy, MFA-scoped tokens, and tamper-evident audit:

```bash
cd backend && pip install -r requirements-dev.txt && pytest tests/ -q
```

Runs in CI on every push (`.github/workflows/ci.yml`).

## Documentation

| Doc | Contents |
|---|---|
| [`COMPLIANCE.md`](COMPLIANCE.md) | Control-by-control HIPAA matrix (implemented / verified / gaps) |
| [`SECURITY.md`](SECURITY.md) | Security posture: controls, resolved findings, open items |
| [`KEY-MANAGEMENT.md`](KEY-MANAGEMENT.md) | Envelope encryption / Vault (KMS) design, unseal, rotation |
| [`DEPLOY.md`](DEPLOY.md) | First-time deployment |
| [`OPERATIONS.md`](OPERATIONS.md) | Infrastructure map + operational runbooks |

Recovery material (Vault unseal keys, tokens, credentials) is kept in a
**gitignored** `secrets/` directory — never committed.

## License

Proprietary — client engagement.
