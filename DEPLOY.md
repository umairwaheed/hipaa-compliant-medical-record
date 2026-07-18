# Deployment (production)

The system runs entirely under a dedicated, unprivileged `hipaa` OS user:

- **App user:** `hipaa` (no login password; runs the API service)
- **Database:** PostgreSQL role + DB `hipaa`, owned by the `hipaa` role, listening
  on localhost only
- **Runtime:** gunicorn + uvicorn workers bound to `127.0.0.1:8000`, managed by
  systemd with a hardened sandbox
- **Edge:** nginx terminates TLS on port **8443**, serves the built SPA, proxies
  `/api`, rate-limits login, and sets HSTS + security headers
- **Backups:** nightly encrypted `pg_dump` via a systemd timer

## Layout

```
/home/hipaa/
  .hipaa_provision.env         # generated DB URL + SECRET_KEY + PHI key (0600)
  .backup_pass                 # AES passphrase for encrypted backups (0600)
  backups/                     # hipaa-<ts>.sql.gz.enc
  hipaa-compliant-medical-record/   # git checkout (dev + deploy env)
    backend/.env               # -> app config (0600)
    backend/.venv
    frontend/dist              # built SPA served by nginx
```

## First-time setup

Provisioning of the `hipaa` user, Postgres role/DB, and secrets is done once (see
`provision`). Then, as the `hipaa` user:

```bash
cd ~/hipaa-compliant-medical-record/backend
cp ~/.hipaa_provision.env .env          # then append ENVIRONMENT / CORS_ORIGINS
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/alembic upgrade head          # create schema
# Create the first administrator (interactive password prompt):
.venv/bin/python -m app.cli create-admin --username admin --full-name "Site Admin"
```

Build the SPA:

```bash
cd ~/hipaa-compliant-medical-record/frontend
npm ci && npm run build
```

Install the system units and nginx config (as root):

```bash
cp deploy/hipaa-api.service       /etc/systemd/system/
cp deploy/hipaa-backup.service    /etc/systemd/system/
cp deploy/hipaa-backup.timer      /etc/systemd/system/
cp deploy/hipaa-ratelimit.conf    /etc/nginx/conf.d/
cp deploy/nginx-hipaa.conf        /etc/nginx/sites-available/hipaa
ln -sf /etc/nginx/sites-available/hipaa /etc/nginx/sites-enabled/hipaa
nginx -t && systemctl reload nginx
systemctl enable --now hipaa-api.service hipaa-backup.timer
```

## Updates (redeploy)

```bash
sudo -u hipaa git -C ~hipaa/hipaa-compliant-medical-record pull
sudo -u hipaa ~hipaa/.../backend/.venv/bin/pip install -r requirements.txt
sudo -u hipaa ~hipaa/.../backend/.venv/bin/alembic upgrade head
sudo -u hipaa bash -c 'cd ~hipaa/.../frontend && npm ci && npm run build'
systemctl restart hipaa-api.service
```

## TLS certificate

The bootstrap uses a self-signed certificate so TLS works immediately by IP. For
production, point a domain at the host and issue a CA certificate:

```bash
certbot --nginx -d records.your-domain.example
```

then set `server_name` and `CORS_ORIGINS` accordingly.

## Operational commands

```bash
python -m app.cli list-users            # audit accounts
python -m app.cli reset-password --username X
python -m app.cli verify-audit          # verify the audit hash chain
systemctl status hipaa-api
journalctl -u hipaa-api -f              # live logs
```

## Notes / remaining organizational items

This deployment satisfies the **technical** safeguards. Before real PHI flows,
the operating organization must also have: a signed BAA covering this host, a
documented risk assessment, and the administrative/physical safeguards. Note this
host is shared with other services — a dedicated, BAA-covered host (or at minimum
documented isolation and shared-responsibility review) is recommended for real
PHI. See `COMPLIANCE.md`.
