"""Patient record endpoints. Every route requires authentication and writes an
audit entry, enforcing HIPAA Access Control (§164.312(a)) and Audit Controls
(§164.312(b))."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import crud, schemas
from ..audit import AuditAction, record
from ..database import get_db
from ..deps import client_ip, get_current_user
from ..models import User

router = APIRouter(prefix="/api/patients", tags=["patients"])


@router.get("", response_model=list[schemas.PatientSummary])
def list_or_search_patients(
    request: Request,
    q: str | None = Query(default=None, description="Search name / MRN / DOB"),
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    if q:
        patients = crud.search_patients(db, q, limit=limit)
        record(
            db,
            action=AuditAction.SEARCH_PATIENTS,
            username=current.username,
            user_id=current.id,
            detail=f"query={q!r} results={len(patients)}",
            ip_address=client_ip(request),
        )
    else:
        patients = crud.list_patients(db, skip=skip, limit=limit)
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
