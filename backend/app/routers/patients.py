"""Patient record endpoints. Every route requires authentication and writes an
audit entry, enforcing HIPAA Access Control (§164.312(a)) and Audit Controls
(§164.312(b)).

Record-level access (minimum necessary): a clinician may only list, search,
view, or edit patients they are assigned to. Administrators have
organization-wide access and manage the assignments. Denied attempts are audited.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import crud, schemas, security
from ..audit import AuditAction, record
from ..database import get_db
from ..deps import client_ip, get_current_user
from ..models import User

router = APIRouter(prefix="/api/patients", tags=["patients"])


def _scope(current: User) -> int | None:
    """None for admins (unrestricted); the user id for clinicians (assigned only)."""
    return None if current.role == "admin" else current.id


def _require_access(db: Session, current: User, patient_id: int, request: Request, action_mrn: str):
    """Raise 403 (and audit the denial) if the caller may not access this patient."""
    if not crud.can_access_patient(db, current, patient_id):
        record(
            db,
            action=AuditAction.ACCESS_DENIED,
            username=current.username,
            user_id=current.id,
            patient_id=patient_id,
            detail=f"not assigned; mrn={action_mrn}",
            ip_address=client_ip(request),
        )
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not assigned to this patient.")


@router.get("", response_model=list[schemas.PatientSummary])
def list_or_search_patients(
    request: Request,
    q: str | None = Query(default=None, description="Search name / MRN / DOB"),
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    scope = _scope(current)
    if q:
        patients = crud.search_patients(db, q, limit=limit, only_for_user_id=scope)
        record(
            db,
            action=AuditAction.SEARCH_PATIENTS,
            username=current.username,
            user_id=current.id,
            # Never store the raw term (it may be a patient name = PHI); a keyed
            # fingerprint preserves correlation without disclosure.
            detail=f"query_fp={security.blind_fingerprint(q)} results={len(patients)}",
            ip_address=client_ip(request),
        )
    else:
        patients = crud.list_patients(db, skip=skip, limit=limit, only_for_user_id=scope)
        record(
            db,
            action=AuditAction.LIST_PATIENTS,
            username=current.username,
            user_id=current.id,
            detail=f"count={len(patients)}",
            ip_address=client_ip(request),
        )
    db.commit()
    return patients


@router.post("", response_model=schemas.PatientDetail, status_code=status.HTTP_201_CREATED)
def create_patient(
    payload: schemas.PatientCreate,
    request: Request,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    try:
        patient = crud.create_patient(db, payload)
        # Auto-assign the creating clinician so they retain access to their record.
        if current.role != "admin":
            crud.assign_patient(db, patient.id, current.id, assigned_by=current.id)
        record(
            db,
            action=AuditAction.CREATE_PATIENT,
            username=current.username,
            user_id=current.id,
            patient_id=patient.id,
            detail=f"mrn={patient.mrn}",
            ip_address=client_ip(request),
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A patient with that MRN already exists.",
        )
    db.refresh(patient)
    return patient


@router.get("/{patient_id}", response_model=schemas.PatientDetail)
def view_patient(
    patient_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    patient = crud.get_patient(db, patient_id)
    if patient is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found.")
    _require_access(db, current, patient.id, request, patient.mrn)
    # Log the PHI access BEFORE returning it.
    record(
        db,
        action=AuditAction.VIEW_PATIENT,
        username=current.username,
        user_id=current.id,
        patient_id=patient.id,
        detail=f"mrn={patient.mrn}",
        ip_address=client_ip(request),
    )
    db.commit()
    return patient


@router.put("/{patient_id}", response_model=schemas.PatientDetail)
def update_patient(
    patient_id: int,
    payload: schemas.PatientUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    patient = crud.get_patient(db, patient_id)
    if patient is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found.")
    _require_access(db, current, patient.id, request, patient.mrn)
    patient, changed = crud.update_patient(db, patient, payload)
    # Record which fields changed — never the PHI values — for integrity/audit.
    record(
        db,
        action=AuditAction.UPDATE_PATIENT,
        username=current.username,
        user_id=current.id,
        patient_id=patient.id,
        detail=f"changed_fields={changed or 'none'}",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(patient)
    return patient


# --------------------------------------------------------------------------- #
# Care-team assignments
# --------------------------------------------------------------------------- #
@router.get("/{patient_id}/assignments", response_model=list[schemas.AssignmentOut])
def list_patient_assignments(
    patient_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    patient = crud.get_patient(db, patient_id)
    if patient is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Patient not found.")
    _require_access(db, current, patient.id, request, patient.mrn)
    return [
        schemas.AssignmentOut(
            user_id=u.id,
            username=u.username,
            full_name=u.full_name,
            role=u.role,
            assigned_at=a.assigned_at,
        )
        for a, u in crud.list_assignments(db, patient_id)
    ]


@router.post("/{patient_id}/assignments", status_code=status.HTTP_201_CREATED)
def assign_clinician(
    patient_id: int,
    payload: schemas.AssignmentCreate,
    request: Request,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """Assign a clinician to a patient's care team. Admin-only — clinicians
    cannot broaden access on their own."""
    if current.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator privileges required.")
    patient = crud.get_patient(db, patient_id)
    if patient is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Patient not found.")
    target = crud.get_user_by_id(db, payload.user_id)
    if target is None or not target.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    created = crud.assign_patient(db, patient_id, target.id, assigned_by=current.id)
    if created:
        record(
            db,
            action=AuditAction.PATIENT_ASSIGNED,
            username=current.username,
            user_id=current.id,
            patient_id=patient_id,
            detail=f"assigned={target.username}",
            ip_address=client_ip(request),
        )
    db.commit()
    return {"assigned": target.username, "created": created}


@router.delete("/{patient_id}/assignments/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def unassign_clinician(
    patient_id: int,
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    if current.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator privileges required.")
    removed = crud.unassign_patient(db, patient_id, user_id)
    if removed:
        record(
            db,
            action=AuditAction.PATIENT_UNASSIGNED,
            username=current.username,
            user_id=current.id,
            patient_id=patient_id,
            detail=f"unassigned_user_id={user_id}",
            ip_address=client_ip(request),
        )
    db.commit()
