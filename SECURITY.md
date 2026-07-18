# Security Posture

This document tracks the application's security controls, the findings that have
been addressed, and the issues that remain open. It complements
[`COMPLIANCE.md`](COMPLIANCE.md) (which maps controls to HIPAA safeguards) and is
kept current so a code review can be reconciled against the *actual* state
rather than an older snapshot.

## Reporting

Security issues should be reported privately to the maintainer, not via public
issues.

## Controls in place

- **Authentication:** bcrypt password hashing + complexity policy; mandatory TOTP
  MFA (no PHI-capable token issued without a verified second factor); account
  lockout after repeated failures.
- **Login timing:** the non-existent-user path runs a dummy bcrypt comparison so
  response time does not reveal whether a username exists (`security.dummy_verify`).
- **Sessions:** short-lived JWTs (15 min absolute) **plus** a 10-minute
  client-side inactivity auto-logout; server-side revocation via a `jti`
  blocklist (logout) and a per-user `token_version` (global "sign out
  everywhere" / password change / forced revocation).
- **Authorization:** every request re-loads the user from the DB and rejects
  inactive accounts; `role` is read from the DB row, not trusted from the JWT
  claim — so deactivation and demotion take effect immediately.
- **PHI at rest:** SSN, contact info, insurance, clinical notes, and TOTP
  secrets encrypted with Fernet (AES-128-CBC + HMAC). Fail-closed on a
  wrong/rotated key.
- **Key management (KMS / envelope encryption):** the Fernet DEK is stored only
  as a Vault **transit** ciphertext (`WRAPPED_PHI_DEK`); the wrapping key (KEK)
  lives in HashiCorp Vault on a **separate host** and never leaves it. At boot
  the app AppRole-authenticates to Vault and unwraps the DEK into memory. **No
  plaintext PHI key exists on the app host** — a stolen app-host disk/backup no
  longer decrypts PHI. Vault runs with TLS, mlock, an audit device, and 8200
  firewalled to the app host only. See `KEY-MANAGEMENT.md`.
- **Audit:** append-only, SHA-256 hash-chained trail; tampering is detectable
  via `/api/audit/verify`. Searched terms are stored as a **keyed fingerprint**,
  never plaintext, so patient names do not leak into the audit log.
- **Record-level access (minimum necessary):** clinicians may only list, search,
  view, and edit patients they are assigned to (care-team model); admins have
  org-wide access and manage assignments; the creating clinician is auto-assigned.
  Denied access returns 403 and is recorded as an `ACCESS_DENIED` audit event.
- **Config:** fails closed — the app refuses to boot without a real
  `SECRET_KEY`, `PHI_ENCRYPTION_KEY`, and a PostgreSQL `DATABASE_URL`; placeholder
  secrets are rejected.
- **Transport / headers:** nginx TLS (1.2/1.3) + HSTS; API bound to localhost;
  strict CSP on the API (`default-src 'none'`) and an app-shell CSP on the SPA
  (`script-src 'self'`, `img-src 'self' data:` for the MFA QR); `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control:
  no-store`. Interactive API docs are disabled in production.
- **Proxy IP:** audit logs record the real client IP from `X-Forwarded-For`,
  which nginx sets to `$remote_addr`. **Safe only because the app is bound to
  127.0.0.1 behind nginx** — if exposed directly, that header is spoofable.

## Recently addressed

Findings from an earlier review, resolved in the production-hardening pass:

| Finding | Resolution |
|---|---|
| Fails open on unset secrets | Fail-closed config validation (`config.py`) |
| Logout client-only; token valid till expiry | `jti` blocklist + `token_version` revocation |
| `/docs` & `/openapi.json` exposed | Disabled when `ENVIRONMENT=production` |
| Audit records proxy IP, not client IP | `X-Forwarded-For` parsing (`deps.client_ip`) |
| Demo credentials in the login UI | Removed |
| Login username-enumeration timing leak | Dummy bcrypt on the null-user path |
| No CSP (token in `sessionStorage`) | CSP on the SPA shell via nginx |
| Absolute token lifetime, no idle logout | 10-minute inactivity auto-logout in the SPA |
| Searched patient names stored plaintext in audit | Keyed blind fingerprint instead of raw term |

## Open items

- **Integrity coverage.** The hash chain protects the audit trail and Fernet
  authenticates encrypted columns, but plaintext identifier columns (name, MRN,
  DOB) are not individually integrity-signed beyond the audit record of changes.
- **Vault unseal / availability.** Vault uses Shamir (manual) unseal, so an
  unattended reboot of the key host leaves PHI undecryptable until an operator
  unseals it. Auto-unseal (cheap cloud KMS or a second Vault) is the documented
  upgrade for unattended recovery. See `KEY-MANAGEMENT.md`.
- **Vault protection level.** Vault OSS uses a software barrier, not a hardware
  HSM; the AppRole `secret_id` on the app host is long-lived (scoped to
  encrypt/decrypt only, revocable). A hardware-backed KEK would require Vault
  Enterprise+HSM or a cloud KMS.
- **JWT signing secret** (`SECRET_KEY`) is still a plaintext value in the app
  host's `.env` (separate from PHI encryption); it could also move to Vault.
- **Automatic logoff nuance.** "Automatic logoff" is now satisfied by the idle
  timeout; the 15-minute JWT is an absolute upper bound, not the primary control.

## Non-code (organizational) prerequisites for real PHI

Signed BAA covering the host, documented risk assessment, workforce training,
incident-response and contingency plans, and — given this runs on a shared host —
a dedicated/BAA-covered environment or a documented isolation review. See
[`COMPLIANCE.md`](COMPLIANCE.md).
