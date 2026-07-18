"""Authentication endpoints (HIPAA §164.312(d) Person or Entity Authentication)."""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import crud, schemas, security
from ..audit import AuditAction, record
from ..config import settings
from ..database import get_db
from ..deps import client_ip, get_current_user
from ..models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=schemas.Token)
def login(payload: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, payload.username)
    ip = client_ip(request)

    if user is None or not security.verify_password(payload.password, user.hashed_password):
        # Log failed attempts by username — surfaces credential-stuffing / misuse.
        record(
            db,
            action=AuditAction.LOGIN_FAILURE,
            username=payload.username,
            ip_address=ip,
            detail="Invalid credentials",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
        )

    token = security.create_access_token(subject=user.username, role=user.role)
    record(
        db,
        action=AuditAction.LOGIN_SUCCESS,
        username=user.username,
        user_id=user.id,
        ip_address=ip,
    )
    db.commit()
    return schemas.Token(
        access_token=token,
        role=user.role,
        full_name=user.full_name,
        expires_in_minutes=settings.access_token_expire_minutes,
    )


@router.get("/me", response_model=schemas.UserOut)
def me(current: User = Depends(get_current_user)):
    return current
