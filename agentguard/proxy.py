"""Transparent forward proxy — govern agents that DON'T use the SDK.

This is the answer to "an agent can just not call our API." Point the agent's
egress at this proxy (``HTTP_PROXY``/``HTTPS_PROXY=http://agent:<api-key>@host:8888``,
set by the operator/container — not the agent) plus a network rule that blocks all
other outbound traffic. Now every request the agent makes with a *plain* HTTP
client is intercepted and governed:

* RBAC policy is evaluated (allow / deny) per destination + method,
* the request body is DLP-scanned to block secret / PII exfiltration,
* every decision is written to the tamper-evident ledger,
* denied requests never reach the origin.

**HTTPS is fully inspected too** (this is the real-traffic case): the proxy
terminates TLS using a certificate signed by the AgentGuard CA — which the operator
installs in the agent's trust store — decrypts the request, governs it, then
re-encrypts to the real origin (verifying the origin's certificate normally). The
agent needs zero code changes and cannot opt out.

Run:  agentguard proxy --port 8888
"""

from __future__ import annotations

import base64
import json
import logging
import socketserver
import ssl
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from .audit.ledger import AuditLedger
from .config import get_settings
from .database import SessionLocal
from .gateway_service import authorize_action
from .models import Agent, AgentStatus, Decision
from .policy.engine import ActionRequest
from .proxy_ca import ProxyCA
from .security import hash_api_key
from .utils import payload_fingerprint

_log = logging.getLogger("agentguard.proxy")

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
}
_MAX_BODY = 5 * 1024 * 1024

# Populated by serve_proxy().
_CA: ProxyCA | None = None


# --------------------------------------------------------------------------- #
# Blocking HTTP-over-socket helpers
# --------------------------------------------------------------------------- #

def _readline(f) -> str:
    return f.readline().decode("latin-1").rstrip("\r\n")


def _read_headers(f) -> dict[str, str]:
    headers: dict[str, str] = {}
    while True:
        line = _readline(f)
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def _read_body(f, headers: dict[str, str]) -> bytes:
    length = int(headers.get("content-length", 0) or 0)
    if length <= 0:
        return b""
    if length > _MAX_BODY:
        raise ValueError("request body too large")
    return f.read(length)


def _write_response(conn, status: int, reason: str, body: bytes,
                    headers: dict | None = None) -> None:
    hdrs = {"Content-Length": str(len(body)), "Connection": "close", **(headers or {})}
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    conn.sendall(head.encode("latin-1") + body)


def _blocked(conn, decision) -> None:
    body = json.dumps({"agentguard": "blocked", "decision": decision.decision,
                       "reason": decision.reason}).encode()
    _write_response(conn, 403, "Forbidden", body, {"Content-Type": "application/json"})


def _api_key(headers: dict[str, str]) -> str | None:
    auth = headers.get("proxy-authorization", "")
    if auth.lower().startswith("basic "):
        try:
            user, _, pw = base64.b64decode(auth[6:]).decode("latin-1").partition(":")
            return pw or user or None
        except (ValueError, UnicodeDecodeError):
            return None
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return None


# --------------------------------------------------------------------------- #
# Governance + forwarding
# --------------------------------------------------------------------------- #

def _resolve_agent(db, key: str) -> Agent | None:
    agent = db.scalar(select(Agent).where(Agent.api_key_hash == hash_api_key(key)))
    if agent and agent.status == AgentStatus.ACTIVE:
        agent.last_seen_at = datetime.now(timezone.utc)
        db.commit()
        return agent
    return None


def _active_agent(db, agent_id: int) -> Agent | None:
    """Re-read an agent, enforcing that it is still ACTIVE.

    ``authorize_action`` re-checks *org* containment on every call but not
    per-agent status, which is resolved once at connection setup. Re-reading per
    request means an agent suspended by auto-containment (alerts_service) stops
    being served on a connection it had already opened, rather than only on its
    next one.

    Deliberately does not touch ``last_seen_at``: a write per request on a
    keep-alive tunnel is not worth the precision.
    """
    agent = db.get(Agent, agent_id)
    return agent if agent is not None and agent.status == AgentStatus.ACTIVE else None


def _govern(db, agent, *, action_type, resource, payload):
    return authorize_action(db, agent, ActionRequest(
        action_type=action_type, resource=resource, payload=payload, metadata={}))


def _forward_and_log(db, agent, method, url, resource, action, headers, body):
    """Forward an allowed request to the origin; return (status, reason, headers, content)."""
    from .tracing import inject_context, span

    fwd = {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP and k.lower() != "host"}
    fwd = inject_context(fwd)  # propagate trace context to the origin
    ledger = AuditLedger(db)
    verify = get_settings().proxy_verify_upstream_tls
    try:
        with span("agentguard.proxy.forward", **{"http.method": method, "agentguard.resource": resource}), \
                httpx.Client(timeout=30.0, follow_redirects=False, verify=verify) as client:
            resp = client.request(method, url, headers=fwd, content=body or None)
    except httpx.HTTPError as exc:
        ledger.append(agent_id=agent.id, agent_name=agent.name,
                      role_name=agent.role.name if agent.role else "",
                      action_type=f"{action}.result", resource=resource,
                      decision=Decision.DENY, reason=f"Upstream failed: {exc}",
                      billable=False, org_id=agent.org_id)
        return None
    ledger.append(agent_id=agent.id, agent_name=agent.name,
                  role_name=agent.role.name if agent.role else "",
                  action_type=f"{action}.result", resource=resource,
                  decision=Decision.ALLOW,
                  reason=f"Proxied {method} {resource} -> {resp.status_code}",
                  payload_hash=payload_fingerprint(resp.text), billable=False, org_id=agent.org_id)
    resp_headers = {k: v for k, v in resp.headers.items()
                    if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"}
    return resp.status_code, resp.reason_phrase or "OK", resp_headers, resp.content


# --------------------------------------------------------------------------- #
# Request handler (threaded, one per connection)
# --------------------------------------------------------------------------- #

class _Handler(socketserver.StreamRequestHandler):
    timeout = 60

    def handle(self) -> None:
        try:
            request_line = _readline(self.rfile)
            if not request_line:
                return
            parts = request_line.split(" ")
            if len(parts) != 3:
                _write_response(self.connection, 400, "Bad Request", b"malformed request")
                return
            method, target, _ver = parts
            headers = _read_headers(self.rfile)

            key = _api_key(headers)
            if not key:
                _write_response(self.connection, 407, "Proxy Authentication Required",
                                b"supply the agent API key via Proxy-Authorization",
                                {"Proxy-Authenticate": 'Basic realm="AgentGuard"'})
                return
            # The database session is scoped to authentication and governance
            # ONLY. A WebSocket tunnel lives as long as the socket does — hours
            # — so holding a pooled connection across one lets db_pool_size +
            # max_overflow tunnels drain the pool and stall the whole control
            # plane (verified: 8 tunnels held 8 connections). Long-lived work is
            # therefore deferred and run after the session is released.
            tunnel: Callable[[], None] | None = None
            with SessionLocal() as db:
                agent = _resolve_agent(db, key)
                if agent is None:
                    _write_response(self.connection, 407, "Proxy Authentication Required",
                                    b"invalid agent API key")
                    return
                if method.upper() == "CONNECT":
                    tunnel = self._handle_connect(db, agent, target)
                else:
                    tunnel = self._handle_plain(db, agent, method, target, headers)
            if tunnel is not None:
                tunnel()
        except Exception:
            _log.exception("proxy connection failed")

    # -- plain HTTP (absolute-form) --------------------------------------
    def _handle_plain(self, db, agent, method, target, headers) -> Callable[[], None] | None:
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.hostname:
            _write_response(self.connection, 400, "Bad Request", b"absolute-form URL required")
            return None

        # WebSocket upgrade: govern the handshake by policy before allowing the
        # connection to be established (the agent cannot open a socket we deny).
        if headers.get("upgrade", "").lower() == "websocket":
            return self._handle_ws_upgrade(db, agent, target, parsed, headers)

        resource = f"http:{parsed.netloc}{parsed.path or '/'}"
        action = f"http.{method.lower()}"
        try:
            body = _read_body(self.rfile, headers)
        except ValueError:
            _write_response(self.connection, 413, "Payload Too Large", b"body too large")
            return None
        self._govern_forward(db, agent, method, target, resource, action, headers, body)
        return None

    # -- WebSocket upgrade (handshake governance) ------------------------
    def _handle_ws_upgrade(self, db, agent, target, parsed, headers) -> Callable[[], None] | None:
        """Govern the handshake now; return the byte pump to run without a session."""
        resource = f"ws:{parsed.netloc}{parsed.path or '/'}"
        gate = _govern(db, agent, action_type="ws.connect", resource=resource, payload=None)
        if gate.decision.decision != Decision.ALLOW:
            _blocked(self.connection, gate.decision)
            return None

        host, port = parsed.hostname, parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        handshake = f"GET {path} HTTP/1.1\r\n" + "".join(
            f"{k}: {v}\r\n" for k, v in headers.items() if k.lower() != "proxy-authorization"
        ) + "\r\n"

        def tunnel() -> None:
            # Runs after the DB session is released: opening the upstream socket
            # and relaying bytes needs no database access, and this is the part
            # that lasts for the entire life of the WebSocket.
            import socket as _socket

            try:
                upstream = _socket.create_connection((host, port), timeout=30)
            except OSError:
                _write_response(self.connection, 502, "Bad Gateway", b"ws upstream unreachable")
                return
            try:
                upstream.sendall(handshake.encode("latin-1"))
                self._pump_bidirectional(self.connection, upstream)
            finally:
                try:
                    upstream.close()
                except OSError:
                    pass

        return tunnel

    @staticmethod
    def _pump_bidirectional(a, b) -> None:
        """Relay bytes between two sockets until either closes (WebSocket tunnel)."""
        import select as _select

        socks = [a, b]
        while True:
            try:
                readable, _, errored = _select.select(socks, [], socks, 60)
            except (OSError, ValueError):
                break
            if errored:
                break
            for src in readable:
                dst = b if src is a else a
                try:
                    data = src.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return

    # -- HTTPS via TLS interception --------------------------------------
    def _handle_connect(self, db, agent, target) -> Callable[[], None] | None:
        """Gate the destination now; return the decrypted tunnel to run sessionless."""
        host, _, port_s = target.partition(":")
        port = int(port_s or 443)

        # Destination-host policy check up front (cheap deny before TLS work).
        gate = _govern(db, agent, action_type="http.connect", resource=f"https:{host}", payload=None)
        if gate.decision.decision != Decision.ALLOW:
            _blocked(self.connection, gate.decision)
            return None

        agent_id = agent.id

        def tunnel() -> None:
            # Deferred so no DB connection is held across the TLS handshake,
            # which mints a per-host leaf certificate and then waits on the
            # *client* — a peer that stalls there would otherwise pin a pooled
            # connection until the 60s socket timeout.
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            assert _CA is not None
            try:
                tls_conn = _CA.context_for_host(host).wrap_socket(
                    self.connection, server_side=True)
            except (ssl.SSLError, OSError):
                return  # agent didn't complete TLS (e.g. no CA installed)

            rfile = tls_conn.makefile("rb")
            try:
                # Handle one or more requests on the decrypted tunnel (keep-alive).
                while True:
                    line = _readline(rfile)
                    if not line:
                        break
                    parts = line.split(" ")
                    if len(parts) != 3:
                        break
                    method, path, _ver = parts
                    headers = _read_headers(rfile)
                    try:
                        body = _read_body(rfile, headers)
                    except ValueError:
                        _write_response(tls_conn, 413, "Payload Too Large", b"body too large")
                        break
                    resource = f"https:{host}{path.split('?', 1)[0]}"
                    action = f"http.{method.lower()}"
                    url = f"https://{host}:{port}{path}"
                    # A fresh, short-lived session per request rather than one
                    # held for the tunnel, and re-reading the agent is what makes
                    # a suspension apply to a connection that is already open.
                    with SessionLocal() as rdb:
                        live = _active_agent(rdb, agent_id)
                        if live is None:
                            _write_response(tls_conn, 403, "Forbidden",
                                            b'{"agentguard":"blocked",'
                                            b'"reason":"agent is suspended"}',
                                            {"Content-Type": "application/json"})
                            break
                        keep = self._govern_forward(rdb, live, method, url, resource, action,
                                                    headers, body, out=tls_conn)
                    if not keep:
                        break
            finally:
                try:
                    tls_conn.close()
                except OSError:
                    pass

        return tunnel

    # -- shared: govern then forward or block ----------------------------
    def _govern_forward(self, db, agent, method, url, resource, action, headers, body,
                        out=None) -> bool:
        conn = out or self.connection
        try:
            payload = json.loads(body) if body else None
        except (ValueError, TypeError):
            payload = body.decode("utf-8", "replace") if body else None

        result = _govern(db, agent, action_type=action, resource=resource, payload=payload)
        if result.decision.decision != Decision.ALLOW:
            _blocked(conn, result.decision)
            return False  # close after a block

        forwarded = _forward_and_log(db, agent, method, url, resource, action, headers, body)
        if forwarded is None:
            _write_response(conn, 502, "Bad Gateway", b"upstream request failed")
            return False
        status, reason, resp_headers, content = forwarded
        _write_response(conn, status, reason, content, resp_headers)
        return False  # Connection: close keeps the handler simple & correct


class _ThreadingProxy(socketserver.ThreadingTCPServer):
    """Thread-per-connection, with a hard ceiling on concurrent connections.

    ``ThreadingTCPServer`` spawns a thread per accepted socket with no bound, so
    anything that can reach the proxy port forces unbounded thread creation just
    by opening sockets. Tunnels are long-lived, so a fixed-size worker pool would
    deadlock instead; a semaphore with immediate rejection is the honest
    trade-off — shed load visibly rather than degrade the whole process.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, max_connections: int, **kwargs):
        self._slots = threading.BoundedSemaphore(max_connections)
        self._max_connections = max_connections
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            _log.warning("proxy at connection limit (%d); rejecting %s",
                         self._max_connections, client_address)
            try:
                _write_response(request, 503, "Service Unavailable",
                                b"proxy connection limit reached")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address) -> None:
        # Released here rather than in shutdown_request so a slot is held for
        # exactly the lifetime of the handling thread, tunnels included.
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def serve_proxy(host: str, port: int) -> None:
    """Run the governing forward proxy (blocking). Call from a thread or the CLI."""
    global _CA
    settings = get_settings()
    _CA = ProxyCA(settings.proxy_ca_dir)
    server = _ThreadingProxy((host, port), _Handler,
                             max_connections=settings.proxy_max_connections)
    _log.info("AgentGuard forward proxy listening on %s:%d", host, port)
    print(f"AgentGuard forward proxy on {host}:{port}")
    print(f"  Agents: HTTP(S)_PROXY=http://agent:<api-key>@{host}:{port}")
    print("  For HTTPS interception, install the CA cert in the agent's trust store:")
    print(f"    {_CA.cert_path}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
