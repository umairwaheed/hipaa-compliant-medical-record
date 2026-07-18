"""Data-access layer for users and patients."""
import secrets

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import models, schemas


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
def get_user_by_username(db: Session, username: str) -> models.User | None:
    return db.scalar(select(models.User).where(models.User.username == username))


# --------------------------------------------------------------------------- #
# Patients
# --------------------------------------------------------------------------- #
def generate_mrn(db: Session) -> str:
    """Generate a unique, non-guessable Medical Record Number."""
    while True:
        mrn = "MRN-" + secrets.token_hex(4).upper()
        if not db.scalar(select(models.Patient.id).where(models.Patient.mrn == mrn)):
            return mrn


def get_patient(db: Session, patient_id: int) -> models.Patient | None:
    return db.get(models.Patient, patient_id)


def list_patients(db: Session, skip: int = 0, limit: int = 50) -> list[models.Patient]:
    stmt = (
        select(models.Patient)
        .order_by(models.Patient.last_name, models.Patient.first_name)
        .offset(skip)
        .limit(limit)
    )
    return list(db.scalars(stmt))


def search_patients(db: Session, query: str, limit: int = 50) -> list[models.Patient]:
    """Search over the plaintext identifier columns only. Encrypted PHI columns
    are intentionally not searchable (see EncryptedString docstring)."""
    like = f"%{query.strip()}%"
    stmt = (
        select(models.Patient)
        .where(
            or_(
                models.Patient.first_name.ilike(like),
                models.Patient.last_name.ilike(like),
                models.Patient.mrn.ilike(like),
                models.Patient.date_of_birth.ilike(like),
            )
        )
        .order_by(models.Patient.last_name, models.Patient.first_name)
        .limit(limit)
    )
    return list(db.scalars(stmt))


def create_patient(db: Session, data: schemas.PatientCreate) -> models.Patient:
    payload = data.model_dump()
    mrn = payload.pop("mrn", None) or generate_mrn(db)
    patient = models.Patient(mrn=mrn, **payload)
    db.add(patient)
    db.flush()  # assign PK without committing; caller commits with the audit row
    return patient


def update_patient(
    db: Session, patient: models.Patient, data: schemas.PatientUpdate
) -> tuple[models.Patient, list[str]]:
    """Apply a partial update. Returns the patient and the list of changed field
    names (used for the audit detail, without logging the PHI values themselves)."""
    changed: list[str] = []
    for field, value in data.model_dump(exclude_unset=True).items():
        if getattr(patient, field) != value:
            setattr(patient, field, value)
            changed.append(field)
    db.flush()
    return patient, changed
