"""FastAPI application entrypoint.

Schema is managed by Alembic migrations run at deploy time — the app does NOT
create tables or seed data on startup (no demo seeding in production).
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings
from .routers import audit, auth, patients, users


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Application-level hardening headers. TLS + HSTS are terminated at nginx;
    these complement it (§164.312(e) Transmission Security)."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"  # never cache PHI responses
        # API returns JSON only; lock the CSP down hard.
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response


app = FastAPI(
    title="HIPAA Medical Record Manager",
    description="EHR implementing HIPAA Security Rule technical safeguards.",
    version="2.0.0",
    # Disable interactive docs in production (they enumerate the PHI API surface).
    docs_url=None if settings.environment == "production" else "/docs",
    redoc_url=None,
    openapi_url=None if settings.environment == "production" else "/openapi.json",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(patients.router)
app.include_router(audit.router)
app.include_router(users.router)


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok"}
