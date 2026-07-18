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


def _scope_to_user(stmt, only_for_user_id: int | None):
    """Restrict a patient query to those assigned to the given user (None = no
    restriction, for admins)."""
    if only_for_user_id is None:
        return stmt
    return stmt.join(
        models.PatientAssignment,
        models.PatientAssignment.patient_id == models.Patient.id,
    ).where(models.PatientAssignment.user_id == only_for_user_id)


def list_patients(
    db: Session, skip: int = 0, limit: int = 50, only_for_user_id: int | None = None
) -> list[models.Patient]:
    stmt = select(models.Patient)
    stmt = _scope_to_user(stmt, only_for_user_id)
    stmt = stmt.order_by(models.Patient.last_name, models.Patient.first_name).offset(skip).limit(limit)
    return list(db.scalars(stmt))


def search_patients(
    db: Session, query: str, limit: int = 50, only_for_user_id: int | None = None
) -> list[models.Patient]:
    """Search over the plaintext identifier columns only. Encrypted PHI columns
    are intentionally not searchable (see EncryptedString docstring). Results are
    scoped to the caller's assigned patients unless unrestricted (admin)."""
    like = f"%{query.strip()}%"
    stmt = select(models.Patient).where(
        or_(
            models.Patient.first_name.ilike(like),
            models.Patient.last_name.ilike(like),
            models.Patient.mrn.ilike(like),
            models.Patient.date_of_birth.ilike(like),
        )
    )
    stmt = _scope_to_user(stmt, only_for_user_id)
    stmt = stmt.order_by(models.Patient.last_name, models.Patient.first_name).limit(limit)
    return list(db.scalars(stmt))


# --------------------------------------------------------------------------- #
# Care-relationship assignments (minimum necessary)
# --------------------------------------------------------------------------- #
def is_assigned(db: Session, patient_id: int, user_id: int) -> bool:
    return db.scalar(
        select(models.PatientAssignment.id).where(
            models.PatientAssignment.patient_id == patient_id,
            models.PatientAssignment.user_id == user_id,
        )
    ) is not None


def can_access_patient(db: Session, user: models.User, patient_id: int) -> bool:
    """Admins have organization-wide access; clinicians only their assignments."""
    return user.role == "admin" or is_assigned(db, patient_id, user.id)


def assign_patient(db: Session, patient_id: int, user_id: int, assigned_by: int | None) -> bool:
    """Idempotent. Returns True if a new assignment was created."""
    if is_assigned(db, patient_id, user_id):
        return False
    db.add(models.PatientAssignment(patient_id=patient_id, user_id=user_id, assigned_by=assigned_by))
    db.flush()
    return True


def unassign_patient(db: Session, patient_id: int, user_id: int) -> bool:
    row = db.scalar(
        select(models.PatientAssignment).where(
            models.PatientAssignment.patient_id == patient_id,
            models.PatientAssignment.user_id == user_id,
        )
    )
    if row is None:
        return False
    db.delete(row)
    db.flush()
    return True


def list_assignments(db: Session, patient_id: int) -> list[tuple[models.PatientAssignment, models.User]]:
    stmt = (
        select(models.PatientAssignment, models.User)
        .join(models.User, models.User.id == models.PatientAssignment.user_id)
        .where(models.PatientAssignment.patient_id == patient_id)
        .order_by(models.User.full_name)
    )
    return list(db.execute(stmt))


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
