"""Audit-log viewing endpoint. Restricted to administrators (minimum-necessary
access to the compliance record itself)."""
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit as audit_mod
from .. import models, schemas
from ..audit import AuditAction, record
from ..database import get_db
from ..deps import client_ip, require_admin
from ..models import User

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[schemas.AuditLogOut])
def list_audit_log(
    request: Request,
    patient_id: int | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
):
    stmt = select(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(limit)
    if patient_id is not None:
        stmt = (
            select(models.AuditLog)
            .where(models.AuditLog.patient_id == patient_id)
            .order_by(models.AuditLog.timestamp.desc())
            .limit(limit)
        )
    logs = list(db.scalars(stmt))
    # Viewing the audit trail is itself an auditable event.
    record(
        db,
        action=AuditAction.VIEW_AUDIT_LOG,
        username=current.username,
        user_id=current.id,
        patient_id=patient_id,
        detail=f"returned={len(logs)}",
        ip_address=client_ip(request),
    )
    db.commit()
    return logs


@router.get("/verify", response_model=schemas.AuditChainStatus)
def verify_audit_chain(db: Session = Depends(get_db), current: User = Depends(require_admin)):
    """Recompute the hash chain and report whether the audit log is intact."""
    return audit_mod.verify_chain(db)
