"""Authentication endpoints (HIPAA §164.312(d) Person or Entity Authentication).

Login is a two-step flow enforcing mandatory MFA:
  1. POST /auth/login            password → short-lived preauth token
  2a. POST /auth/mfa/verify      TOTP code (enrolled users) → full token
  2b. POST /auth/mfa/enroll      (not-yet-enrolled) → secret + QR
      POST /auth/mfa/enroll/verify  TOTP code → enables MFA + full token
No full (PHI-capable) token is ever issued without a verified second factor.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import crud, schemas, security
from ..audit import AuditAction, record
from ..config import settings
from ..database import get_db
from ..deps import client_ip, get_current_jti, get_current_user, get_preauth_user
from ..models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _issue_full(db: Session, user: User) -> schemas.Token:
    token, _ = security.create_access_token(user.username, user.role, user.token_version)
    return schemas.Token(
        access_token=token,
        role=user.role,
        full_name=user.full_name,
        expires_in_minutes=settings.access_token_expire_minutes,
    )


@router.post("/login", response_model=schemas.LoginResult)
def login(payload: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, payload.username)
    ip = client_ip(request)
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect username or password.")

    if user is None:
        # Uniform response; still audit the attempt against the supplied name.
        record(db, action=AuditAction.LOGIN_FAILURE, username=payload.username,
               ip_address=ip, detail="unknown user")
        db.commit()
        raise invalid

    if crud.is_locked(user):
        record(db, action=AuditAction.LOGIN_LOCKED, username=user.username,
               user_id=user.id, ip_address=ip)
        db.commit()
        raise HTTPException(status.HTTP_423_LOCKED,
                            "Account temporarily locked due to failed attempts. Try again later.")

    if not user.is_active or not security.verify_password(payload.password, user.hashed_password):
        locked = crud.register_failed_login(db, user)
        record(db, action=AuditAction.LOGIN_LOCKED if locked else AuditAction.LOGIN_FAILURE,
               username=user.username, user_id=user.id, ip_address=ip,
               detail="invalid credentials")
        db.commit()
        raise invalid

    # Password correct — reset counters, issue a preauth (MFA-pending) token.
    crud.reset_login_failures(db, user)
    record(db, action=AuditAction.LOGIN_SUCCESS, username=user.username,
           user_id=user.id, ip_address=ip, detail="password ok; mfa pending")
    db.commit()
    preauth, _ = security.create_preauth_token(user.username, user.role, user.token_version)
    return schemas.LoginResult(enrolled=user.mfa_enabled, preauth_token=preauth)


@router.post("/mfa/verify", response_model=schemas.Token)
def mfa_verify(payload: schemas.MfaCode, request: Request,
               user: User = Depends(get_preauth_user), db: Session = Depends(get_db)):
    """Second factor for already-enrolled users."""
    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is not enrolled for this account.")
    if not security.verify_totp(user.mfa_secret, payload.code):
        record(db, action=AuditAction.MFA_FAILURE, username=user.username,
               user_id=user.id, ip_address=client_ip(request))
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication code.")
    record(db, action=AuditAction.MFA_SUCCESS, username=user.username,
           user_id=user.id, ip_address=client_ip(request))
    db.commit()
    return _issue_full(db, user)


@router.post("/mfa/enroll", response_model=schemas.MfaEnrollStart)
def mfa_enroll(user: User = Depends(get_preauth_user), db: Session = Depends(get_db)):
    """Begin enrollment: generate + store a provisional secret and return a QR.
    MFA is not active until the code is verified."""
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is already enrolled.")
    secret = security.generate_totp_secret()
    user.mfa_secret = secret  # stored encrypted; mfa_enabled stays False until verify
    db.commit()
    uri = security.totp_provisioning_uri(secret, user.username)
    return schemas.MfaEnrollStart(secret=secret, otpauth_uri=uri,
                                  qr_data_uri=security.totp_qr_data_uri(uri))


@router.post("/mfa/enroll/verify", response_model=schemas.Token)
def mfa_enroll_verify(payload: schemas.MfaCode, request: Request,
                      user: User = Depends(get_preauth_user), db: Session = Depends(get_db)):
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is already enrolled.")
    if not user.mfa_secret or not security.verify_totp(user.mfa_secret, payload.code):
        record(db, action=AuditAction.MFA_FAILURE, username=user.username,
               user_id=user.id, ip_address=client_ip(request), detail="enrollment")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication code.")
    user.mfa_enabled = True
    record(db, action=AuditAction.MFA_ENROLLED, username=user.username,
           user_id=user.id, ip_address=client_ip(request))
    db.commit()
    return _issue_full(db, user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, jti_exp=Depends(get_current_jti),
           user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Revoke the current session's token (single-session logout)."""
    jti, exp = jti_exp
    crud.revoke_token(db, jti, exp)
    record(db, action=AuditAction.LOGOUT, username=user.username,
           user_id=user.id, ip_address=client_ip(request))
    db.commit()


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(payload: schemas.PasswordChange, request: Request,
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not security.verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect.")
    try:
        security.validate_password_policy(payload.new_password)
    except security.PasswordPolicyError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    user.hashed_password = security.hash_password(payload.new_password)
    user.token_version += 1  # invalidate all existing sessions on password change
    record(db, action=AuditAction.PASSWORD_CHANGED, username=user.username,
           user_id=user.id, ip_address=client_ip(request))
    db.commit()


@router.get("/me", response_model=schemas.UserOut)
def me(current: User = Depends(get_current_user)):
    return current
