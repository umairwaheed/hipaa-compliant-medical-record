"""Admin user-management endpoints (administrators only).

Every action is audited. Guards prevent an admin from locking themselves out
(no self-deactivation). Password/MFA/deactivate actions bump the target's
token_version so any of their existing sessions are immediately revoked.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import crud, schemas, security
from ..audit import AuditAction, record
from ..database import get_db
from ..deps import client_ip, require_admin
from ..models import User

router = APIRouter(prefix="/api/users", tags=["users"])


def _get_target(db: Session, user_id: int) -> User:
    user = crud.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return user


@router.get("", response_model=list[schemas.UserAdminOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return crud.list_all_users(db)


@router.post("", response_model=schemas.UserAdminOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: schemas.UserCreate, request: Request,
                db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    try:
        security.validate_password_policy(payload.password)
    except security.PasswordPolicyError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    try:
        user = crud.create_user(
            db,
            username=payload.username,
            full_name=payload.full_name,
            role=payload.role,
            hashed_password=security.hash_password(payload.password),
        )
        record(db, action=AuditAction.USER_CREATED, username=admin.username, user_id=admin.id,
               detail=f"created={payload.username} role={payload.role}", ip_address=client_ip(request))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "That username is already taken.")
    db.refresh(user)
    return user


@router.post("/{user_id}/reset-mfa", response_model=schemas.UserAdminOut)
def reset_mfa(user_id: int, request: Request,
              db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Clear a user's MFA so they must re-enroll at next login (e.g. lost device)."""
    user = _get_target(db, user_id)
    user.mfa_secret = None
    user.mfa_enabled = False
    user.token_version += 1  # revoke current sessions
    record(db, action=AuditAction.USER_MFA_RESET, username=admin.username, user_id=admin.id,
           detail=f"target={user.username}", ip_address=client_ip(request))
    db.commit()
    db.refresh(user)
    return user


@router.post("/{user_id}/unlock", response_model=schemas.UserAdminOut)
def unlock(user_id: int, request: Request,
           db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = _get_target(db, user_id)
    crud.reset_login_failures(db, user)
    record(db, action=AuditAction.USER_UNLOCKED, username=admin.username, user_id=admin.id,
           detail=f"target={user.username}", ip_address=client_ip(request))
    db.commit()
    db.refresh(user)
    return user


@router.post("/{user_id}/deactivate", response_model=schemas.UserAdminOut)
def deactivate(user_id: int, request: Request,
               db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = _get_target(db, user_id)
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot deactivate your own account.")
    user.is_active = False
    user.token_version += 1  # revoke current sessions
    record(db, action=AuditAction.USER_DEACTIVATED, username=admin.username, user_id=admin.id,
           detail=f"target={user.username}", ip_address=client_ip(request))
    db.commit()
    db.refresh(user)
    return user


@router.post("/{user_id}/activate", response_model=schemas.UserAdminOut)
def activate(user_id: int, request: Request,
             db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = _get_target(db, user_id)
    user.is_active = True
    record(db, action=AuditAction.USER_ACTIVATED, username=admin.username, user_id=admin.id,
           detail=f"target={user.username}", ip_address=client_ip(request))
    db.commit()
    db.refresh(user)
    return user


@router.post("/{user_id}/reset-password", response_model=schemas.UserAdminOut)
def reset_password(user_id: int, payload: schemas.AdminPasswordReset, request: Request,
                   db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = _get_target(db, user_id)
    try:
        security.validate_password_policy(payload.new_password)
    except security.PasswordPolicyError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    user.hashed_password = security.hash_password(payload.new_password)
    user.token_version += 1  # revoke current sessions
    crud.reset_login_failures(db, user)
    record(db, action=AuditAction.USER_PASSWORD_RESET, username=admin.username, user_id=admin.id,
           detail=f"target={user.username}", ip_address=client_ip(request))
    db.commit()
    db.refresh(user)
    return user
