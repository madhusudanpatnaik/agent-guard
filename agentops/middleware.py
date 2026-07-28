"""Security and observability middleware for the AgentOps control plane.

Three concerns, each implemented as a Starlette middleware:

1. **SecurityHeadersMiddleware** — injects hardening headers (CSP, X-Frame-Options,
   HSTS, etc.) into every HTTP response so the operator console and API are
   protected even when served behind a permissive reverse proxy.

2. **BodySizeLimitMiddleware** — rejects request bodies above a configurable
   ceiling *before* they are read into memory, preventing a trivial OOM / DoS.

3. **AccessLogMiddleware** — emits one structured JSON log line per request
   with method, path, status, and latency, suitable for shipping to a SIEM.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_access_log = logging.getLogger("agentops.access")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Append defensive HTTP headers to every response."""

    def __init__(self, app, *, csp: str = ""):
        super().__init__(app)
        self.csp = csp or (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = self.csp
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # HSTS: instruct browsers to only use HTTPS for this domain (1 year).
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the configured ceiling.

    This fires *before* the body is consumed, so an oversized payload never
    allocates memory. Requests without a Content-Length header are allowed
    through (chunked transfers are bounded downstream by framework defaults).
    """

    def __init__(self, app, *, max_bytes: int = 1_048_576):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            return JSONResponse(
                {"detail": f"Request body too large (max {self.max_bytes} bytes)"},
                status_code=413,
            )
        return await call_next(request)


class AccessLogMiddleware(BaseHTTPMiddleware):
    """Emit a structured JSON log line for every request."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)
        event = {
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": elapsed_ms,
            "client": request.client.host if request.client else None,
        }
        _access_log.info(json.dumps(event))
        return response
