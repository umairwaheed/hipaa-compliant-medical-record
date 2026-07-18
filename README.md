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

The Security Rule defines **five technical-safeguard standards** (45 CFR
§164.312), each with required (R) and addressable (A) implementation
specifications. All five standards are implemented here; the table below maps
each to its code. `(R)`/`(A)` mark the spec type. See
[`COMPLIANCE.md`](COMPLIANCE.md) for the full control-by-control matrix and
[`SECURITY.md`](SECURITY.md) for the security posture.

### 1. Access Control — §164.312(a)(1)
| Spec | Implementation |
|---|---|
| Unique user identification `(a)(2)(i)` **(R)** | Per-user accounts; JWT identifies the actor on every request; role-based access. `app/deps.py`, `app/models.py` |
| Emergency access procedure `(a)(2)(ii)` **(R)** | Administrators have organization-wide access (documented as the current break-glass path). `COMPLIANCE.md` |
| Automatic logoff `(a)(2)(iii)` **(A)** | 10-min idle timeout + 15-min absolute JWT + server-side revocation. `frontend/src/auth.jsx`, `app/security.py` |
| Encryption & decryption `(a)(2)(iv)` **(A)** | `EncryptedString` (Fernet) encrypts SSN, contact, insurance, notes, TOTP secrets; key from a KMS (Vault) envelope. `app/security.py`, `app/keyprovider.py` |
| Record-level access (minimum necessary) | Clinicians see only assigned patients; denied access is audited. `app/routers/patients.py` |

### 2. Audit Controls — §164.312(b) **(R)**
Append-only, **keyed (HMAC-SHA256) hash-chained** `AuditLog` records every login, MFA event, search, view, create, update, and access denial. Tampering breaks the chain and is caught by `/api/audit/verify`. `app/audit.py`

### 3. Integrity — §164.312(c)(1) **(R)**
| Spec | Implementation |
|---|---|
| Protect PHI from improper alteration `(c)(1)` | Updates record which fields changed; the keyed audit chain detects alteration/deletion of the log. `app/crud.py`, `app/audit.py` |
| Authenticate ePHI `(c)(2)` **(A)** | Fernet is authenticated encryption — tampered ciphertext fails closed (`<decryption-error>`). `app/security.py` |

### 4. Person or Entity Authentication — §164.312(d) **(R)**
bcrypt password hashing + complexity policy; **mandatory TOTP MFA** (no PHI token without a verified second factor); account lockout across the password **and** MFA steps; nginx rate-limits credential endpoints. `app/routers/auth.py`, `app/security.py`

### 5. Transmission Security — §164.312(e)(1)
| Spec | Implementation |
|---|---|
| Integrity controls `(e)(2)(i)` **(A)** | nginx TLS 1.2/1.3 + HSTS; app bound to localhost behind the proxy. `deploy/nginx-hipaa.conf` |
| Encryption `(e)(2)(ii)` **(A)** | TLS in transit; app sets `no-store`, `nosniff`, strict CSP, `X-Frame-Options: DENY`. `app/main.py` |

**Additional hardening:** fail-closed secrets (no boot without a real encryption
key / JWT secret / Postgres URL), no default credentials, no interactive API docs
in production, and the *Minimum Necessary* projection on list/search (no SSN/notes
until an audited single-record view).

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
