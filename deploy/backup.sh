#!/usr/bin/env bash
# Encrypted PostgreSQL backup for the HIPAA database (§164.308(a)(7) Contingency
# Plan). Dumps, compresses, and encrypts with AES-256 before anything touches
# disk, then prunes backups older than the retention window.
#
# Restore:
#   openssl enc -d -aes-256-cbc -pbkdf2 -pass file:$PASS_FILE -in FILE.sql.gz.enc \
#     | gunzip | psql "$DATABASE_URL"
set -euo pipefail

BACKUP_DIR=/home/hipaa/backups
PASS_FILE=/home/hipaa/.backup_pass          # 0600, owned by hipaa
RETENTION_DAYS=14
ENV_FILE=/home/hipaa/hipaa-compliant-medical-record/backend/.env

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
PG_URL=${DATABASE_URL/postgresql+psycopg/postgresql}

mkdir -p "$BACKUP_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$BACKUP_DIR/hipaa-$STAMP.sql.gz.enc"

pg_dump "$PG_URL" \
  | gzip \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -pass file:"$PASS_FILE" -out "$OUT"
chmod 600 "$OUT"
echo "backup written: $OUT"

# Prune old encrypted backups.
find "$BACKUP_DIR" -name 'hipaa-*.sql.gz.enc' -mtime +"$RETENTION_DAYS" -delete
echo "pruned backups older than ${RETENTION_DAYS}d"
