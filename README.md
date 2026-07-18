# HIPAA-Compliant Medical Record Manager

A portfolio demo of an electronic health record (EHR) system that implements the
**HIPAA Security Rule technical safeguards** (45 CFR §164.312). Built with
**FastAPI + SQLAlchemy + SQLite** on the backend and **React (Vite)** on the front end.

> ⚠️ **Demo project.** It contains only synthetic PHI and ships with default
> demo credentials. It is a reference implementation of the *technical*
> safeguards — a production deployment additionally requires administrative and
> physical safeguards, Business Associate Agreements, risk assessments, and a
> hardened infrastructure. See [Production hardening](#production-hardening).

## Features

- Create, view, edit, and search patient records
- Secure authentication with role-based access (admin / clinician)
- Every access to PHI recorded in an immutable audit trail
- Sensitive PHI encrypted at rest

## How each HIPAA technical safeguard is implemented

| Safeguard (45 CFR §164.312) | Implementation |
|---|---|
| **Access Control** §164.312(a)(1) — unique user IDs, only authorized access | Per-user accounts; every API route requires a valid JWT; RBAC (`require_admin`) gates the audit log. `backend/app/deps.py` |
| **Automatic Logoff** §164.312(a)(2)(iii) | Short-lived JWTs (default 15 min); the SPA clears the session and redirects on any `401`. `security.py`, `frontend/src/api.js` |
| **Encryption at rest** §164.312(a)(2)(iv) | `EncryptedString` SQLAlchemy type encrypts SSN, contact info, insurance, and clinical notes with Fernet (AES-128-CBC + HMAC) before they touch SQLite. `security.py` |
| **Audit Controls** §164.312(b) | Append-only `AuditLog` records every login, list, search, view, create, and update — with user, action, patient, timestamp, and IP. `audit.py`, `models.py` |
| **Integrity** §164.312(c)(1) | Updates record exactly which fields changed; Fernet's HMAC detects tampering with encrypted data at rest. |
| **Person/Entity Authentication** §164.312(d) | bcrypt-hashed passwords; failed logins are themselves audited. `routers/auth.py` |
| **Transmission Security** §164.312(e)(1) | App sets `no-store`, `nosniff`, `X-Frame-Options: DENY`; TLS/HSTS terminates at the proxy in production. `main.py` |
| **Minimum Necessary** (Privacy Rule) | List/search return a reduced `PatientSummary` (no SSN/notes); full PHI only on explicit single-record view (which is audited). |

## Architecture

```
backend/                 FastAPI service
  app/
    config.py            Settings & secrets (env-driven)
    database.py          SQLAlchemy engine/session
    security.py          Password hashing, JWT, PHI field encryption
    models.py            User, Patient, AuditLog
    schemas.py           Pydantic request/response models
    crud.py              Data-access layer
    audit.py             Audit-log writer
    deps.py              Auth + RBAC dependencies
    routers/             auth, patients, audit endpoints
    seed.py              Tables + demo data
    main.py              App wiring, security headers, CORS
frontend/                React (Vite) SPA
  src/pages/             Login, PatientList, PatientView, PatientForm, AuditLog
```

## Running locally

### 1. Backend (http://localhost:8000)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Optional but recommended: create a persistent encryption key + secret
cp .env.example .env
python -c "from cryptography.fernet import Fernet; print('PHI_ENCRYPTION_KEY=' + Fernet.generate_key().decode())" >> .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env

uvicorn app.main:app --reload
```

Tables are created and demo data seeded automatically on startup.
Interactive API docs: http://localhost:8000/docs

### 2. Frontend (http://localhost:5173)

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` to the backend.

### Demo accounts

| Role | Username | Password |
|---|---|---|
| Administrator (can view the audit log) | `admin` | `Admin123!` |
| Clinician | `dr.smith` | `Clinician123!` |

## Try it

1. Sign in as `dr.smith` → browse, search, create, and edit patients.
2. Open a patient → note the "this access has been recorded" banner.
3. Sign in as `admin` → open **Audit Log** to see every access, including your own.
4. Inspect `backend/hipaa_demo.db` with a SQLite viewer — the `ssn`,
   `clinical_notes`, etc. columns are ciphertext, while the audit trail is intact.

## Design notes & trade-offs

- **Searchable vs. encrypted fields.** Name, MRN, and DOB are stored in plaintext
  so clinicians can search; they remain protected by access control + audit.
  Highly sensitive fields are encrypted and therefore *not* directly searchable.
  A production system needing search over encrypted values would add a **blind
  index** (a keyed HMAC of a normalized value) rather than store plaintext.
- **Audit immutability.** The app only ever appends to `AuditLog`. In production
  this is reinforced with append-only/WORM storage or log shipping to a separate
  system the app cannot rewrite.
- **Key management.** The Fernet key lives in an env var here; production uses a
  KMS/secret manager with rotation and envelope encryption.

## Production hardening

Not implemented in this demo, required for real PHI:

- TLS everywhere + HSTS; disable HTTP
- Managed secrets/KMS with key rotation; envelope encryption
- Account lockout, MFA, password policies, session revocation lists
- Full-database encryption (e.g. Postgres + pgcrypto/at-rest disk encryption)
- Log aggregation to tamper-evident storage; alerting on anomalous access
- Automated backups with tested restore; data-retention & disposal policy
- Signed Business Associate Agreements with every vendor touching PHI
- Administrative & physical safeguards, workforce training, risk assessment

## License

Provided as a portfolio/demonstration sample.
