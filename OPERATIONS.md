# Operations Runbook

How the deployed system is laid out and how to operate it. No secrets appear in
this file — recovery material lives in the gitignored `secrets/vault-recovery.md`
and in 0600 files on the servers (paths noted below).

## Architecture

Two hosts, deliberately separated so a compromise of the app host does not yield
the PHI encryption key:

```
  App host: internal-one (13.140.128.200)        Key host: demo-one (13.140.131.111)
  ┌──────────────────────────────────────┐       ┌────────────────────────────────┐
  │ nginx  ── TLS/HSTS ── hipaa.getprixite│       │ HashiCorp Vault (systemd)      │
  │   ├─ serves SPA (frontend/dist)       │  TLS  │   transit engine: key hipaa-phi│
  │   └─ proxies /api → 127.0.0.1:8000    │ 8200  │   policy hipaa-phi (enc/dec)   │
  │ hipaa-api (gunicorn+uvicorn, systemd) │◄─────►│   AppRole hipaa-app            │
  │   run as user `hipaa`                 │AppRole│   file audit device           │
  │ PostgreSQL 16 (localhost) db `hipaa`  │       │   raft storage, mlock, TLS     │
  │ nightly encrypted pg_dump (timer)     │       │ 8200/8201 firewalled → app host│
  └──────────────────────────────────────┘       └────────────────────────────────┘
```

- **DNS:** Cloudflare zone `getprixite.com`, A record `hipaa.getprixite.com` →
  13.140.128.200, **DNS-only (grey cloud)** so Cloudflare is not in the PHI path.
- **TLS:** Let's Encrypt via `certbot --dns-cloudflare` (auto-renews).
- **Repo:** `github.com/umairwaheed/hipaa-compliant-medical-record`; CI runs the
  compliance suite + frontend build on every push.
- **PHI key:** envelope encryption — the Fernet DEK is stored only as a Vault
  transit ciphertext; the KEK never leaves Vault. No plaintext PHI key on the app
  host. See `KEY-MANAGEMENT.md`.

## App host layout (`/home/hipaa/`)

| Path | What |
|---|---|
| `hipaa-compliant-medical-record/` | git checkout (dev + deploy) |
| `.../backend/.env` | app config (KEY_PROVIDER=vault, wrapped DEK, AppRole secret_id, DB URL, SECRET_KEY) — 0600 |
| `.../backend/.venv` | Python 3.12 venv |
| `.../frontend/dist` | built SPA served by nginx |
| `.hipaa_provision.env` | SECRET_KEY + DATABASE_URL (0600) |
| `vault-ca.pem` | Vault TLS CA (0644) |
| `.backup_pass` | backup encryption passphrase (0600) |
| `.admin_bootstrap` | initial admin credential (0600) |
| `backups/` | `hipaa-<ts>.sql.gz.enc` (14-day retention) |

systemd units on the app host: `hipaa-api.service`, `hipaa-backup.timer`.
On the key host: `vault.service`.

## Runbooks

### Vault sealed after a reboot (PHI can't be decrypted)
Vault uses manual (Shamir) unseal. After a reboot of demo-one it comes up
**sealed**; a running app keeps working (key is in memory) but any restart of
`hipaa-api` fails closed until Vault is unsealed.

```bash
# On demo-one — repeat with 3 different unseal keys from secrets/vault-recovery.md
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/opt/vault/tls/vault-cert.pem
vault operator unseal   # paste key 1
vault operator unseal   # paste key 2
vault operator unseal   # paste key 3
vault status            # Sealed=false
# Then, if the app had restarted while sealed:
ssh internal-one systemctl restart hipaa-api
```
(To make reboots hands-off, enable auto-unseal — see `KEY-MANAGEMENT.md`.)

### Restart / check the app
```bash
ssh internal-one
systemctl status hipaa-api          # or: restart hipaa-api
journalctl -u hipaa-api -f          # live logs
curl -s http://127.0.0.1:8000/api/health
```

### Deploy an update
```bash
sudo -u hipaa -H bash
cd ~/hipaa-compliant-medical-record && git pull
cd backend && .venv/bin/pip install -r requirements.txt && .venv/bin/alembic upgrade head
cd ../frontend && npm ci && npm run build
exit
systemctl restart hipaa-api
```

### User administration
```bash
# via CLI (app host, as hipaa, in backend/ with .env loaded):
.venv/bin/python -m app.cli create-admin --username NAME --full-name "Full Name"
.venv/bin/python -m app.cli reset-password --username NAME
.venv/bin/python -m app.cli list-users
# or via the web UI: sign in as admin → Users page (create, reset MFA, lock, etc.)
```

### Verify the audit trail is intact (tamper-evident hash chain)
```bash
.venv/bin/python -m app.cli verify-audit    # or GET /api/audit/verify as admin
```

### Backups
Nightly encrypted `pg_dump` at 02:30 (systemd timer) → `~/backups/*.sql.gz.enc`.
```bash
# manual backup:
ssh internal-one systemctl start hipaa-backup.service
# restore (passphrase in secrets/vault-recovery.md or ~/.backup_pass):
openssl enc -d -aes-256-cbc -pbkdf2 -pass file:/home/hipaa/.backup_pass \
  -in ~/backups/FILE.sql.gz.enc | gunzip | psql "$DATABASE_URL"
```

### Key rotation
```bash
# KEK (Vault) — cheap, no data re-encryption:
ssh demo-one 'export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/opt/vault/tls/vault-cert.pem; \
  vault login <root>; vault write -f transit/keys/hipaa-phi/rotate'
# DEK (the data key) — requires re-encrypting rows via MultiFernet; see KEY-MANAGEMENT.md.
```

### Rotate a leaked credential
See the "If something leaks" section of `secrets/vault-recovery.md`.

## Documentation index

| Doc | Contents |
|---|---|
| `README.md` | Overview, features, HIPAA technical-safeguard mapping |
| `COMPLIANCE.md` | Control-by-control HIPAA matrix (implemented / verified / gaps) |
| `SECURITY.md` | Security posture: controls, resolved findings, open items |
| `KEY-MANAGEMENT.md` | Envelope encryption / Vault design, unseal, rotation |
| `DEPLOY.md` | First-time deployment steps |
| `OPERATIONS.md` | This file — infra map + runbooks |
| `secrets/vault-recovery.md` | **gitignored** — recovery material (not in repo) |

## Outstanding (organizational — not code)

Signed BAA covering both hosts, documented risk assessment, workforce training,
incident-response & contingency plans. `demo-one` must be treated as
production-grade now that it holds the PHI KEK. See `COMPLIANCE.md`.
