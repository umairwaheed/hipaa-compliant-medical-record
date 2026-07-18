"""Tamper-evident audit logging (HIPAA §164.312(b)).

Every entry is chained to the previous one with SHA-256, so any later deletion
or modification of a row breaks the chain and is detectable via
``verify_chain``. Appends are serialized with a Postgres transaction-level
advisory lock so concurrent requests cannot fork the chain.
"""
import hashlib
from datetime import datetime, timezone

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from . import models

# Arbitrary constant identifying the audit-chain advisory lock.
_AUDIT_LOCK_KEY = 743922100


class AuditAction:
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGIN_LOCKED = "LOGIN_LOCKED"
    MFA_SUCCESS = "MFA_SUCCESS"
    MFA_FAILURE = "MFA_FAILURE"
    MFA_ENROLLED = "MFA_ENROLLED"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    LIST_PATIENTS = "LIST_PATIENTS"
    SEARCH_PATIENTS = "SEARCH_PATIENTS"
    VIEW_PATIENT = "VIEW_PATIENT"
    CREATE_PATIENT = "CREATE_PATIENT"
    UPDATE_PATIENT = "UPDATE_PATIENT"
    VIEW_AUDIT_LOG = "VIEW_AUDIT_LOG"


def _compute_hash(
    *,
    timestamp: datetime,
    username: str,
    action: str,
    patient_id: int | None,
    detail: str | None,
    ip_address: str | None,
    prev_hash: str | None,
) -> str:
    # Canonicalize to UTC so the hash is stable across DB round-trips (Postgres
    # returns timestamptz in the session timezone, which may not be UTC).
    ts_iso = timestamp.astimezone(timezone.utc).isoformat()
    payload = "|".join(
        [
            ts_iso,
            username,
            action,
            str(patient_id or ""),
            detail or "",
            ip_address or "",
            prev_hash or "",
        ]
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def record(
    db: Session,
    *,
    action: str,
    username: str,
    user_id: int | None = None,
    patient_id: int | None = None,
    detail: str | None = None,
    ip_address: str | None = None,
) -> None:
    """Append a hash-chained audit entry. Committed by the caller within its
    transaction so the audit record and the action it describes succeed or fail
    together."""
    # Serialize chain construction across concurrent transactions.
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})

    prev_hash = db.scalar(
        select(models.AuditLog.row_hash).order_by(models.AuditLog.id.desc()).limit(1)
    )
    ts = datetime.now(timezone.utc)
    row_hash = _compute_hash(
        timestamp=ts,
        username=username,
        action=action,
        patient_id=patient_id,
        detail=detail,
        ip_address=ip_address,
        prev_hash=prev_hash,
    )
    db.add(
        models.AuditLog(
            timestamp=ts,
            action=action,
            username=username,
            user_id=user_id,
            patient_id=patient_id,
            detail=detail,
            ip_address=ip_address,
            prev_hash=prev_hash,
            row_hash=row_hash,
        )
    )


def verify_chain(db: Session) -> dict:
    """Recompute the chain and report the first broken link, if any."""
    rows = list(db.scalars(select(models.AuditLog).order_by(models.AuditLog.id.asc())))
    prev = None
    for row in rows:
        expected = _compute_hash(
            timestamp=row.timestamp,
            username=row.username,
            action=row.action,
            patient_id=row.patient_id,
            detail=row.detail,
            ip_address=row.ip_address,
            prev_hash=prev,
        )
        if row.prev_hash != prev or row.row_hash != expected:
            return {"intact": False, "broken_at_id": row.id, "count": len(rows)}
        prev = row.row_hash
    return {"intact": True, "broken_at_id": None, "count": len(rows)}
