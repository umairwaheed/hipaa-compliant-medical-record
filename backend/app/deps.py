"""FastAPI dependencies for authentication and role-based access control."""
from datetime import datetime, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import crud, models, security
from .database import get_db

_bearer = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def client_ip(request: Request) -> str | None:
    # Trust the proxy's client IP header (nginx sets X-Forwarded-For).
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _decode(credentials: HTTPAuthorizationCredentials | None) -> dict:
    if credentials is None:
        raise _UNAUTHORIZED
    try:
        return security.decode_access_token(credentials.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise _UNAUTHORIZED


def _load_valid_user(db: Session, payload: dict) -> models.User:
    username = payload.get("sub")
    if not username:
        raise _UNAUTHORIZED
    user = crud.get_user_by_username(db, username)
    if user is None or not user.is_active:
        raise _UNAUTHORIZED
    # Global revocation: token issued before a token_version bump is dead.
    if payload.get("ver") != user.token_version:
        raise _UNAUTHORIZED
    # Single-session revocation: jti on the blocklist.
    jti = payload.get("jti")
    if jti and crud.is_token_revoked(db, jti):
        raise _UNAUTHORIZED
    return user


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    """Full authenticated access — requires a completed-MFA (scope=full) token."""
    payload = _decode(credentials)
    if payload.get("scp") != security.SCOPE_FULL:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Multi-factor authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _load_valid_user(db, payload)


def get_preauth_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    """Password verified, MFA step pending — only valid on the MFA endpoints."""
    payload = _decode(credentials)
    if payload.get("scp") != security.SCOPE_PREAUTH:
        raise _UNAUTHORIZED
    return _load_valid_user(db, payload)


def get_current_jti(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> tuple[str, datetime]:
    """Return (jti, expiry) of the presented token, for logout/revocation."""
    payload = _decode(credentials)
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    return payload["jti"], exp


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required.",
        )
    return user
