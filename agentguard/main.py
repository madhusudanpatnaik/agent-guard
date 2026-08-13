"""FastAPI application factory and entrypoint for the AgentGuard control plane."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text

from . import __version__
from .background import start_background_tasks, stop_background_tasks
from .config import get_settings
from .database import SessionLocal, init_db
from .logging_config import configure_logging
from .middleware import AccessLogMiddleware, BodySizeLimitMiddleware, SecurityHeadersMiddleware
from .models import Organization, User
from .routers import (
    agents,
    alerts,
    approvals,
    audit,
    auth,
    compliance,
    connectors,
    dashboard,
    detectors,
    gateway,
    orgs,
    roles,
    scim,
    simulator,
)
from .security import hash_password

STATIC_DIR = Path(__file__).parent / "static"


def bootstrap_admin() -> None:
    """Create the default organization + bootstrap operator (idempotent)."""
    settings = get_settings()
    with SessionLocal() as db:
        if db.scalar(select(User).limit(1)):
            return
        org = db.scalar(select(Organization).where(Organization.slug == "default"))
        if not org:
            org = Organization(name="Default", slug="default")
            db.add(org)
            db.flush()
        db.add(
            User(
                org_id=org.id,
                email=settings.bootstrap_admin_email.lower().strip(),
                password_hash=hash_password(settings.bootstrap_admin_password),
                role="admin",
                is_superadmin=True,
            )
        )
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bootstrap_admin()
    start_background_tasks()
    yield
    stop_background_tasks()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    # Optional OpenTelemetry tracing (no-op unless enabled + packages installed).
    from .tracing import configure_tracing

    configure_tracing()

    # Fail closed: never serve a governance control plane with checked-in
    # default credentials or signing keys in production.
    problems = settings.production_problems()
    if problems:
        raise RuntimeError(
            "Refusing to start in production with insecure configuration:\n  - "
            + "\n  - ".join(problems)
        )

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Control plane for governing autonomous AI agents — RBAC enforcement, "
            "data-exfiltration prevention, human-in-the-loop approvals, and a "
            "tamper-evident audit ledger."
        ),
        lifespan=lifespan,
    )

    # --- Middleware stack (order matters: outermost first) ---

    # Auth is carried in the Authorization/X-API-Key headers, not cookies, so we
    # never need credentialed CORS. Disable it whenever origins are wildcarded
    # (browsers reject "*" + credentials anyway, and it is a footgun).
    wildcard = "*" in settings.cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=not wildcard,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security headers (CSP, XFO, HSTS, etc.)
    app.add_middleware(SecurityHeadersMiddleware, csp=settings.csp_policy)

    # Request body size limiter (rejects oversized bodies with 413)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)

    # Structured access logging
    app.add_middleware(AccessLogMiddleware)

    # --- Routers ---
    for module in (auth, orgs, roles, agents, connectors, gateway, approvals, audit,
                   dashboard, simulator, alerts, scim, detectors, compliance):
        app.include_router(module.router, prefix="/api")

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok", "service": settings.app_name, "version": __version__}

    @app.get("/ready", tags=["meta"])
    def readiness() -> JSONResponse:
        """Readiness probe: confirms the database is reachable."""
        try:
            with SessionLocal() as db:
                db.execute(text("SELECT 1"))
            return JSONResponse({"status": "ready", "database": "ok"})
        except Exception as exc:
            return JSONResponse(
                {"status": "not_ready", "database": str(exc)},
                status_code=503,
            )

    if STATIC_DIR.exists():
        app.mount("/console", StaticFiles(directory=STATIC_DIR, html=True), name="console")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    else:  # pragma: no cover - only if the package is stripped of static assets
        @app.get("/", include_in_schema=False)
        def index_json() -> JSONResponse:
            return JSONResponse({"service": settings.app_name, "docs": "/docs"})

    return app


app = create_app()
