"""Database models.

PHI is split into two categories:
- Searchable identifiers stored in plaintext (first/last name, MRN, DOB) so the
  app can offer clinician search. These are still PHI and protected by the
  access-control + audit layers.
- Highly sensitive fields (SSN, contact info, insurance, clinical notes) stored
  with `EncryptedString` so they are ciphertext at rest.
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base
from .security import EncryptedString


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="clinician")  # admin | clinician
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Patient(Base):
    __tablename__ = "patients"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Medical Record Number — human-facing unique identifier.
    mrn: Mapped[str] = mapped_column(String(32), unique=True, index=True)

    # Searchable identifiers (plaintext, protected by access control + audit).
    first_name: Mapped[str] = mapped_column(String(64), index=True)
    last_name: Mapped[str] = mapped_column(String(64), index=True)
    date_of_birth: Mapped[str] = mapped_column(String(10))  # ISO YYYY-MM-DD

    # Highly sensitive PHI — encrypted at rest.
    ssn: Mapped[str | None] = mapped_column(EncryptedString(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(EncryptedString(255), nullable=True)
    email: Mapped[str | None] = mapped_column(EncryptedString(255), nullable=True)
    address: Mapped[str | None] = mapped_column(EncryptedString(512), nullable=True)
    insurance_provider: Mapped[str | None] = mapped_column(EncryptedString(255), nullable=True)
    insurance_id: Mapped[str | None] = mapped_column(EncryptedString(255), nullable=True)
    clinical_notes: Mapped[str | None] = mapped_column(EncryptedString(4096), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class AuditLog(Base):
    """Immutable, append-only record of every access to or change of PHI.

    HIPAA §164.312(b) Audit Controls. Rows are never updated or deleted by the
    application.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(64))  # denormalized so history survives user deletion
    action: Mapped[str] = mapped_column(String(48), index=True)
    patient_id: Mapped[int | None] = mapped_column(
        ForeignKey("patients.id"), nullable=True, index=True
    )
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
