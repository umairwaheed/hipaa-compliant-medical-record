"""FastAPI application entrypoint."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings
from .routers import audit, auth, patients
from .seed import seed


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline hardening headers. In production, TLS termination + HSTS at the
    proxy is what satisfies §164.312(e) Transmission Security; these are the
    application-level complements."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"  # never cache PHI responses
        return response


app = FastAPI(
    title="HIPAA-Compliant Medical Record Manager",
    description="Demo EHR illustrating HIPAA Security Rule technical safeguards.",
    version="1.0.0",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(patients.router)
app.include_router(audit.router)


@app.on_event("startup")
def on_startup() -> None:
    seed()


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok"}
