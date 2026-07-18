"""Database models.

PHI is split into two categories:
- Searchable identifiers stored in plaintext (first/last name, MRN, DOB) so the
  app can offer clinician search. These are still PHI and protected by the
  access-control + audit layers.
- Highly sensitive fields (SSN, contact info, insurance, clinical notes) stored
  with ``EncryptedString`` so they are ciphertext at rest.
"""

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base
from .security import EncryptedString


def _utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="clinician")  # admin | clinician
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Multi-factor authentication (TOTP). Secret encrypted at rest.
    mfa_secret: Mapped[str | None] = mapped_column(EncryptedString(255), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Brute-force protection.
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Bumping this invalidates every previously issued token for the user
    # (logout-everywhere / password change / forced revocation).
    token_version: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    @property
    def locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > _utcnow()


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
    """Immutable, append-only, hash-chained record of every access to or change
    of PHI (HIPAA §164.312(b)).

    Each row stores the SHA-256 hash of the previous row plus its own content,
    forming a chain: altering or deleting any row breaks every subsequent hash,
    making tampering detectable. Rows are never updated or deleted by the app.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    username: Mapped[str] = mapped_column(
        String(64)
    )  # denormalized: history survives user deletion
    action: Mapped[str] = mapped_column(String(48), index=True)
    patient_id: Mapped[int | None] = mapped_column(
        ForeignKey("patients.id"), nullable=True, index=True
    )
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Hash chain.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(String(64))


class PatientAssignment(Base):
    """Care-relationship linking a clinician to a patient. Enforces HIPAA
    'minimum necessary' — a clinician may only access patients they are assigned
    to. Admins are not listed here; they have organization-wide access."""

    __tablename__ = "patient_assignments"
    __table_args__ = (UniqueConstraint("patient_id", "user_id", name="uq_patient_user"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey("patients.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    assigned_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class TokenBlocklist(Base):
    """Revoked JWT identifiers (single-session logout). Rows past ``expires_at``
    can be purged since the token would be expired anyway."""

    __tablename__ = "token_blocklist"

    jti: Mapped[str] = mapped_column(String(32), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
