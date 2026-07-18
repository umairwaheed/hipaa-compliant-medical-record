"""FastAPI dependencies for authentication and role-based access control."""
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import crud, models, security
from .database import get_db

_bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    try:
        payload = security.decode_access_token(credentials.credentials)
    except jwt.ExpiredSignatureError:
        # Automatic logoff — expired session (§164.312(a)(2)(iii)).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise unauthorized

    username = payload.get("sub")
    if not username:
        raise unauthorized
    user = crud.get_user_by_username(db, username)
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required.",
        )
    return user
