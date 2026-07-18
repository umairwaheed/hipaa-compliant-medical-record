"""Pydantic request/response schemas."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResult(BaseModel):
    """Response to the password step.

    - ``mfa_required=True`` with ``enrolled=True``  → submit a TOTP code to
      /auth/mfa/verify using ``preauth_token``.
    - ``mfa_required=True`` with ``enrolled=False`` → enroll via
      /auth/mfa/enroll then /auth/mfa/enroll/verify using ``preauth_token``.
    """
    mfa_required: bool = True
    enrolled: bool
    preauth_token: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    full_name: str
    expires_in_minutes: int


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class MfaEnrollStart(BaseModel):
    secret: str
    otpauth_uri: str
    qr_data_uri: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    full_name: str
    role: str
    mfa_enabled: bool


class UserAdminOut(BaseModel):
    """Fuller projection for the admin user-management view."""
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    full_name: str
    role: str
    mfa_enabled: bool
    is_active: bool
    locked: bool
    failed_login_count: int
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    full_name: str = Field(min_length=1, max_length=128)
    role: str = Field(pattern=r"^(admin|clinician)$")
    password: str = Field(min_length=12)


class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=12)


# --------------------------------------------------------------------------- #
# Patients
# --------------------------------------------------------------------------- #
class PatientBase(BaseModel):
    first_name: str = Field(min_length=1, max_length=64)
    last_name: str = Field(min_length=1, max_length=64)
    date_of_birth: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$", description="ISO date YYYY-MM-DD")
    ssn: str | None = Field(default=None, max_length=11)
    phone: str | None = None
    email: EmailStr | None = None
    address: str | None = None
    insurance_provider: str | None = None
    insurance_id: str | None = None
    clinical_notes: str | None = None


class PatientCreate(PatientBase):
    mrn: str | None = Field(default=None, description="Auto-generated if omitted")


class PatientUpdate(BaseModel):
    first_name: str | None = Field(default=None, min_length=1, max_length=64)
    last_name: str | None = Field(default=None, min_length=1, max_length=64)
    date_of_birth: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    ssn: str | None = None
    phone: str | None = None
    email: EmailStr | None = None
    address: str | None = None
    insurance_provider: str | None = None
    insurance_id: str | None = None
    clinical_notes: str | None = None


class PatientSummary(BaseModel):
    """Minimum-necessary projection for list/search views (no full PHI)."""
    model_config = ConfigDict(from_attributes=True)
    id: int
    mrn: str
    first_name: str
    last_name: str
    date_of_birth: str
    updated_at: datetime


class PatientDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    mrn: str
    first_name: str
    last_name: str
    date_of_birth: str
    ssn: str | None = None
    phone: str | None = None
    email: str | None = None
    address: str | None = None
    insurance_provider: str | None = None
    insurance_id: str | None = None
    clinical_notes: str | None = None
    created_at: datetime
    updated_at: datetime


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    username: str
    action: str
    patient_id: int | None
    detail: str | None
    ip_address: str | None


class AuditChainStatus(BaseModel):
    intact: bool
    broken_at_id: int | None
    count: int
