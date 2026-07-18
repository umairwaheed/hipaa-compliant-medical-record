"""Pydantic request/response schemas."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    full_name: str
    expires_in_minutes: int


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    full_name: str
    role: str


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
