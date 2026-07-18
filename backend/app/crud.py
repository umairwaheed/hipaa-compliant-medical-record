"""Data-access layer for users, patients, and token revocation."""
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import models, schemas
from .config import settings


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Users / authentication state
# --------------------------------------------------------------------------- #
def get_user_by_username(db: Session, username: str) -> models.User | None:
    return db.scalar(select(models.User).where(models.User.username == username))


def get_user_by_id(db: Session, user_id: int) -> models.User | None:
    return db.get(models.User, user_id)


def list_all_users(db: Session) -> list[models.User]:
    return list(db.scalars(select(models.User).order_by(models.User.id)))


def create_user(db: Session, *, username: str, full_name: str, role: str, hashed_password: str) -> models.User:
    user = models.User(
        username=username, full_name=full_name, role=role, hashed_password=hashed_password
    )
    db.add(user)
    db.flush()
    return user


def is_locked(user: models.User) -> bool:
    return user.locked_until is not None and user.locked_until > _utcnow()


def register_failed_login(db: Session, user: models.User) -> bool:
    """Increment the failure counter; lock the account past the threshold.
    Returns True if the account is now locked."""
    user.failed_login_count += 1
    if user.failed_login_count >= settings.max_failed_logins:
        user.locked_until = _utcnow() + timedelta(minutes=settings.lockout_minutes)
        user.failed_login_count = 0
        return True
    return False


def reset_login_failures(db: Session, user: models.User) -> None:
    user.failed_login_count = 0
    user.locked_until = None


# --------------------------------------------------------------------------- #
# Token revocation
# --------------------------------------------------------------------------- #
def revoke_token(db: Session, jti: str, expires_at: datetime) -> None:
    db.merge(models.TokenBlocklist(jti=jti, expires_at=expires_at))


def is_token_revoked(db: Session, jti: str) -> bool:
    return db.get(models.TokenBlocklist, jti) is not None


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
    names (for the audit detail, without logging the PHI values themselves)."""
    changed: list[str] = []
    for field, value in data.model_dump(exclude_unset=True).items():
        if getattr(patient, field) != value:
            setattr(patient, field, value)
            changed.append(field)
    db.flush()
    return patient, changed
