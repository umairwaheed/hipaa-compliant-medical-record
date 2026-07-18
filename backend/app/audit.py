"""Helper for writing audit-log entries (HIPAA §164.312(b))."""
from sqlalchemy.orm import Session

from . import models


class AuditAction:
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LIST_PATIENTS = "LIST_PATIENTS"
    SEARCH_PATIENTS = "SEARCH_PATIENTS"
    VIEW_PATIENT = "VIEW_PATIENT"
    CREATE_PATIENT = "CREATE_PATIENT"
    UPDATE_PATIENT = "UPDATE_PATIENT"
    VIEW_AUDIT_LOG = "VIEW_AUDIT_LOG"


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
    """Append an audit entry. Committed by the caller within its transaction so
    the audit record and the action it describes succeed or fail together."""
    db.add(
        models.AuditLog(
            action=action,
            username=username,
            user_id=user_id,
            patient_id=patient_id,
            detail=detail,
            ip_address=ip_address,
        )
    )
