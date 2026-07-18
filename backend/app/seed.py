"""Create tables and seed demo users + sample patients.

Idempotent: safe to run repeatedly. Demo credentials only — a real deployment
must never seed default accounts.
"""
from sqlalchemy import select

from . import models, security
from .config import settings
from .database import Base, SessionLocal, engine


SAMPLE_PATIENTS = [
    dict(
        mrn="MRN-1001",
        first_name="Alice", last_name="Johnson", date_of_birth="1985-03-12",
        ssn="123-45-6789", phone="+1-555-0101", email="alice.johnson@example.com",
        address="742 Evergreen Terrace, Springfield",
        insurance_provider="BlueCross", insurance_id="BC-88231",
        clinical_notes="Type 2 diabetes, managed with metformin. Last A1C 6.8%.",
    ),
    dict(
        mrn="MRN-1002",
        first_name="Bob", last_name="Martinez", date_of_birth="1972-11-30",
        ssn="987-65-4321", phone="+1-555-0102", email="bob.martinez@example.com",
        address="128 Maple Street, Portland",
        insurance_provider="Aetna", insurance_id="AE-40912",
        clinical_notes="Hypertension. On lisinopril 10mg daily. BP well controlled.",
    ),
    dict(
        mrn="MRN-1003",
        first_name="Carol", last_name="Nguyen", date_of_birth="1990-07-08",
        ssn="456-78-9012", phone="+1-555-0103", email="carol.nguyen@example.com",
        address="55 Ocean Ave, San Diego",
        insurance_provider="Kaiser", insurance_id="KP-11220",
        clinical_notes="Seasonal allergies. Prescribed cetirizine as needed.",
    ),
]


def seed() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.scalar(select(models.User.id)) is None:
            db.add_all([
                models.User(
                    username=settings.seed_admin_username,
                    full_name="System Administrator",
                    hashed_password=security.hash_password(settings.seed_admin_password),
                    role="admin",
                ),
                models.User(
                    username=settings.seed_clinician_username,
                    full_name="Dr. Jane Smith",
                    hashed_password=security.hash_password(settings.seed_clinician_password),
                    role="clinician",
                ),
            ])
            print("Seeded demo users.")

        if db.scalar(select(models.Patient.id)) is None:
            db.add_all([models.Patient(**p) for p in SAMPLE_PATIENTS])
            print("Seeded sample patients.")

        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    seed()
    print("Database ready.")
