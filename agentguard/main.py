"""FastAPI application factory and entrypoint for the AgentGuard control plane."""

from __future__ import annotations

import logging
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

_startup_log = logging.getLogger("agentguard.startup")

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


def check_vault_key() -> str | None:
    """Warn at startup if stored connector secrets can't be decrypted.

    The vault key is derived from VAULT_KEY (falling back to SECRET_KEY), so
    changing either one orphans every credential encrypted under the old value.
    Without this check that failure is invisible until the first governed
    execute/query, which then returns a request-time 400 saying
    "could not be decrypted (key rotated?)" — confusing for the very common case
    where the operator never rotated anything: they ran `agentguard seed` before
    setting AGENTGUARD_SECRET_KEY (the README tells them to set it), and the demo
    data was encrypted under the dev default.

    Deliberately a warning, not a refusal: a partially-completed
    `rotate-vault-key` run is a legitimate state an operator must be able to boot
    into and finish. Returns the message so tests can assert on it.
    """
    from .models import Connector
    from .vault import decrypt_secret

    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(Connector).where(Connector.auth_secret_encrypted != "").limit(25)
            ).all()
            if not rows:
                return None
            broken = []
            for c in rows:
                try:
                    decrypt_secret(c.auth_secret_encrypted)
                except ValueError:
                    broken.append(c.name)
    except Exception:  # noqa: BLE001 - never let a diagnostic stop startup
        return None

    if not broken:
        return None
    msg = (
        f"{len(broken)} connector credential(s) cannot be decrypted with the current "
        f"vault key ({', '.join(sorted(broken)[:5])}"
        f"{', …' if len(broken) > 5 else ''}). Governed execute/query against them "
        "will fail at request time. Most likely AGENTGUARD_SECRET_KEY (or "
        "AGENTGUARD_VAULT_KEY) changed after these were stored — e.g. seeded before "
        "setting a key. Fix: re-run `agentguard rotate-vault-key --new-key <current>` "
        "with the OLD key still in the environment, re-enter the credentials, or "
        "re-seed a dev database."
    )
    _startup_log.warning(msg)
    return msg


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bootstrap_admin()
    check_vault_key()
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
