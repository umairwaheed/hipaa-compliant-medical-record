# HIPAA Compliance Matrix

This document maps the **HIPAA Security Rule** (45 CFR Part 164, Subpart C) — plus
the relevant Privacy, Breach Notification, and Organizational requirements — to
their implementation in this project, how each control is **verified**, and the
**gaps** that remain for a production system handling real PHI.

> ⚠️ **Read this first.** No software is "HIPAA compliant" on its own. HIPAA
> compliance is a property of an **organization and its processes**, achieved
> through the combination of technology, administrative policy, physical
> controls, signed Business Associate Agreements (BAAs), and ongoing audits.
> There is no body that certifies code as compliant; compliance is self-attested
> by the covered entity / business associate and enforced by HHS OCR.
>
> This project implements and verifies the **technical safeguards**. It is a
> reference implementation and demo — it uses synthetic PHI, demo credentials,
> and demo-grade key management. The administrative and physical safeguards, and
> the production-hardening items below, are **out of scope for the code** and
> would be the responsibility of the deploying organization.

## Status legend

| Symbol | Meaning |
|---|---|
| ✅ **Implemented** | Built into the application and verified in this repo |
| 🟡 **Demo-grade** | Implemented, but not to production strength (noted inline) |
| 🏢 **Organizational** | Cannot be satisfied by code — requires policy, people, or infrastructure |

---

## 1. Technical Safeguards — 45 CFR §164.312

The layer this codebase actually owns.

| Standard / Implementation Spec | CFR | Status | Implementation & where | Verification |
|---|---|---|---|---|
| **Access Control** — Unique user identification (R) | §164.312(a)(2)(i) | ✅ | Per-user accounts; JWT `sub` identifies the actor on every request. `app/models.py`, `app/deps.py` | Each audit row carries the acting username |
| Access Control — Emergency access procedure (R) | §164.312(a)(2)(ii) | 🏢 | Not implemented — break-glass access is an operational policy | — |
| Access Control — Automatic logoff (A) | §164.312(a)(2)(iii) | ✅ | Short-lived JWT (default 15 min); SPA clears session + redirects on any 401. `app/security.py`, `frontend/src/api.js` | Expired token → 401; UI bounces to login |
| Access Control — Encryption & decryption (A) | §164.312(a)(2)(iv) | 🟡 | `EncryptedString` type encrypts SSN, contact info, insurance, notes with Fernet (AES-128-CBC + HMAC) before DB write. `app/security.py`, `app/models.py` | Raw SQLite inspection shows ciphertext; no plaintext SSN on disk. **Demo gap:** key in env var, not a KMS |
| Role-based authorization (part of Access Control std) | §164.312(a)(1) | ✅ | Every route requires auth; `require_admin` gates the audit log. `app/deps.py`, `app/routers/audit.py` | Clinician → `/audit` returns **403** |
| **Audit Controls** — record & examine activity (R) | §164.312(b) | ✅ | Append-only `AuditLog`: login (incl. failures), list, search, view, create, update — with user, patient, timestamp, IP, detail. `app/audit.py`, `app/models.py` | Every action produces a row; failed logins captured |
| **Integrity** — protect PHI from improper alteration (R) | §164.312(c)(1) | 🟡 | Updates record exactly which fields changed; Fernet HMAC detects tampering of encrypted values at rest. `app/crud.py` returns changed-field list | Update audit detail lists changed fields. **Gap:** no per-record cryptographic version chain / WORM store |
| Integrity — authenticate ePHI (A) | §164.312(c)(2) | 🟡 | Fernet authenticated encryption fails closed on tampering (`<decryption-error>`) rather than returning bad data | Wrong key → decryption error, never silent ciphertext |
| **Person or Entity Authentication** (R) | §164.312(d) | 🟡 | bcrypt-hashed passwords; failed logins audited. `app/security.py`, `app/routers/auth.py` | Passwords never stored plaintext. **Gap:** no MFA, lockout, or password policy |
| **Transmission Security** — integrity controls (A) | §164.312(e)(2)(i) | 🏢 | TLS at the proxy in production provides integrity in transit | Deployment concern |
| Transmission Security — encryption (A) | §164.312(e)(2)(ii) | 🟡 | App sets `no-store`, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. `app/main.py`. TLS/HSTS terminates at the proxy in prod | Security headers present on responses. **Gap:** TLS not enforced by the demo itself |

*(R) = Required, (A) = Addressable under the Security Rule.*

---

## 2. Administrative Safeguards — 45 CFR §164.308

The **largest** safeguard category, and the one most breaches fail on. Almost
entirely organizational — code cannot satisfy these.

| Standard | CFR | Status | Note |
|---|---|---|---|
| Security Management Process — **Risk Analysis** (R) | §164.308(a)(1)(ii)(A) | 🏢 | A documented risk assessment is the foundation of the entire Security Rule |
| Security Management Process — Risk Management (R) | §164.308(a)(1)(ii)(B) | 🏢 | Remediation plan derived from the risk analysis |
| Sanction Policy (R) | §164.308(a)(1)(ii)(C) | 🏢 | Workforce discipline for violations |
| Information System Activity Review (R) | §164.308(a)(1)(ii)(D) | 🟡 | The audit log **enables** this; the *review process* (who reviews, how often) is organizational |
| Assigned Security Responsibility (R) | §164.308(a)(2) | 🏢 | Named Security Official |
| Workforce Security / clearance / termination (A) | §164.308(a)(3) | 🏢 | Onboarding & offboarding procedures |
| Information Access Management (R) | §164.308(a)(4) | 🟡 | RBAC model exists in code; the *authorization policy* is organizational |
| Security Awareness & Training (A) | §164.308(a)(5) | 🏢 | Workforce training program |
| Security Incident Procedures (R) | §164.308(a)(6) | 🏢 | Incident response plan |
| **Contingency Plan** — backups, DR, emergency mode (R) | §164.308(a)(7) | 🏢 | Backup, disaster recovery, tested restore |
| Evaluation (R) | §164.308(a)(8) | 🏢 | Periodic compliance re-assessment |
| **Business Associate Agreements** (R) | §164.308(b)(1) | 🏢 | Signed BAA with every vendor touching PHI (hosting, email, etc.) |

---

## 3. Physical Safeguards — 45 CFR §164.310

Facility and hardware controls — the responsibility of the hosting environment
and the organization.

| Standard | CFR | Status | Note |
|---|---|---|---|
| Facility Access Controls (A) | §164.310(a)(1) | 🏢 | Datacenter physical security (handled by cloud provider under BAA) |
| Workstation Use / Security (R) | §164.310(b)–(c) | 🏢 | Endpoint policies for devices accessing PHI |
| Device & Media Controls — disposal, re-use, backup (R/A) | §164.310(d)(1) | 🏢 | Secure media disposal and data-retention policy |

---

## 4. Privacy Rule (selected) — 45 CFR §164.500+

| Requirement | Status | Implementation |
|---|---|---|
| **Minimum Necessary** — §164.502(b) | ✅ | List/search return a reduced `PatientSummary` (no SSN/notes); full PHI only on an explicit, audited single-record view. `app/schemas.py`, `app/routers/patients.py` |
| Individual right of access / amendment — §164.524, §164.526 | 🟡 | View/edit exist; formal patient-facing request workflows are out of scope |
| Accounting of disclosures — §164.528 | 🟡 | The audit log provides the underlying access record; a patient-facing report is not built |

---

## 5. Breach Notification Rule — 45 CFR §164.400+

| Requirement | Status | Note |
|---|---|---|
| Breach detection & notification (§164.404–410) | 🏢 | The audit log supports detection; notification obligations (to individuals, HHS, media) are organizational processes |
| Encryption safe harbor | 🟡 | PHI encrypted at rest (Fernet) contributes toward the encryption safe harbor **if** keys are managed to NIST standards — which the demo's env-var key does **not** meet |

---

## 6. How the technical controls were verified

Evidence gathered in this repo (not just asserted):

- **Encryption at rest** — inspected the raw SQLite file directly; `ssn` and
  `clinical_notes` columns are Fernet ciphertext (`gAAAAA…`), and a substring
  search confirmed no plaintext SSN is present on disk.
- **Access control** — unauthenticated request → `401`; a clinician token
  against `GET /api/audit` → `403`.
- **Audit completeness** — login, list, search, view, create, and update each
  produced an audit row; a deliberately failed login was recorded as
  `LOGIN_FAILURE`.
- **Fail-closed integrity** — decryption with a wrong key returns
  `<decryption-error>`, never raw ciphertext masquerading as PHI.

**Recommended next step:** encode these as an automated test suite in CI so the
guarantees cannot regress — e.g. a test that fails the build if any patient
route is missing its auth dependency, or if a new PHI column is not wrapped in
`EncryptedString`.

---

## 7. Production-hardening gaps (must close for real PHI)

Summarized from the README. None of these are implemented in this demo:

- TLS everywhere + HSTS; HTTP disabled
- Managed secrets / **KMS with key rotation** and envelope encryption (replaces the env-var Fernet key)
- MFA, account lockout, password policy, session revocation
- Full-database encryption at rest (e.g. managed Postgres + disk encryption) instead of SQLite
- Log aggregation to **tamper-evident / WORM** storage; alerting on anomalous access
- Automated, tested backups; documented data-retention & disposal policy
- Signed **BAAs** with every vendor touching PHI
- Documented **risk assessment**, workforce training, incident-response and contingency plans

---

## Honest bottom line

> This project **implements and verifies the HIPAA Security Rule technical
> safeguards**. Achieving full HIPAA compliance for real PHI additionally
> requires the administrative and physical safeguards, a documented risk
> assessment, Business Associate Agreements, and hardened infrastructure — which
> are the responsibility of the deploying organization and are documented here as
> the path to production.
