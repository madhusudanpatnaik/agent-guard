"""Resource-exhaustion regressions for the forward proxy.

A WebSocket tunnel is long-lived by design — minutes to hours. If the governing
proxy holds a pooled database connection for the tunnel's whole lifetime, then
``db_pool_size + max_overflow`` concurrent tunnels consume every connection the
control plane has, and *the entire API stalls* — authorization, the ledger, the
console. Governance failing open because someone opened some WebSockets is a
control-plane outage, so this is a hard invariant, not a tuning concern.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def ws_upstream():
    """A socket server that accepts and holds the connection open (like a real WS)."""
    port = _free_port()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept_loop() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (OSError, socket.timeout):
                continue
            held.append(conn)  # hold it open; never respond

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(timeout=2)
    for c in held:
        c.close()
    srv.close()


@pytest.fixture
def proxy_port():
    from agentguard.proxy import serve_proxy
    port = _free_port()
    threading.Thread(target=lambda: serve_proxy("127.0.0.1", port), daemon=True).start()
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return port


def _ws_agent(client, admin_headers):
    role = client.post("/api/roles", json={"name": "wsbot"},
                       headers=admin_headers).json()
    client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers,
                json={"effect": "allow", "resource": "ws:**", "actions": ["ws.connect"]})
    agent = client.post("/api/agents", json={"name": "WSBot", "role_id": role["id"]},
                        headers=admin_headers).json()
    return agent["api_key"]


def _open_tunnel(key: str, proxy_port: int, upstream: int) -> socket.socket:
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    raw.sendall((
        f"GET http://127.0.0.1:{upstream}/ws HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{upstream}\r\n"
        f"Proxy-Authorization: Bearer {key}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    ).encode())
    return raw


def test_websocket_tunnels_do_not_hold_database_connections(
    client, admin_headers, ws_upstream, proxy_port
):
    """Long-lived tunnels must release their DB session before pumping bytes."""
    from agentguard.database import engine

    key = _ws_agent(client, admin_headers)
    tunnels = [_open_tunnel(key, proxy_port, ws_upstream) for _ in range(8)]
    try:
        # Give the proxy time to authorize each handshake and enter the pump.
        deadline = time.time() + 5
        while time.time() < deadline and engine.pool.checkedout() > 0:
            time.sleep(0.1)

        checked_out = engine.pool.checkedout()
        assert checked_out == 0, (
            f"{checked_out} DB connections still held while {len(tunnels)} WebSocket "
            "tunnels are open — enough concurrent tunnels would exhaust the pool "
            "and stall the entire control plane"
        )
    finally:
        for t in tunnels:
            t.close()


def test_suspended_agent_is_refused_on_a_reused_proxy_client(
    client, admin_headers, proxy_port, monkeypatch, tmp_path
):
    """Suspension must take effect immediately, not at the next process restart.

    Note what this does and does not prove. ``_govern_forward`` always responds
    ``Connection: close``, so the decrypted CONNECT tunnel serves exactly one
    request today and the per-request re-read inside that loop is defence in
    depth rather than a live exploit fix. What is verifiable now is the property
    that matters operationally: once auto-containment suspends an agent, an
    already-configured client gets refused on its very next request.
    """
    import http.server
    import ssl as _ssl

    import httpx

    import agentguard.proxy as proxymod
    from agentguard.config import get_settings
    from agentguard.database import SessionLocal
    from agentguard.models import Agent, AgentStatus
    from tests.test_proxy import _agent_with_policy, _self_signed

    monkeypatch.setattr(get_settings(), "proxy_verify_upstream_tls", False)

    certfile, keyfile = _self_signed(tmp_path)
    origin_port = _free_port()

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b'{"origin":"reached"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", origin_port), _H)
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    try:
        key = _agent_with_policy(client, admin_headers, "https:127.0.0.1**",
                                 ["http.connect", "http.get"])
        with SessionLocal() as db:
            agent_id = db.query(Agent).filter(Agent.name == "ProxyBot").one().id

        ca_ctx = _ssl.create_default_context(cafile=str(proxymod._CA.cert_path))
        with httpx.Client(proxy=f"http://agent:{key}@127.0.0.1:{proxy_port}",
                          verify=ca_ctx, timeout=15) as c:
            assert c.get(f"https://127.0.0.1:{origin_port}/data").status_code == 200

            # Suspend the agent, exactly as auto-containment does.
            with SessionLocal() as db:
                db.get(Agent, agent_id).status = AgentStatus.SUSPENDED
                db.commit()

            # Refused either at CONNECT (407, surfaced by httpx as ProxyError)
            # or inside the tunnel (403) — both are a denial, which is the point.
            try:
                refused = c.get(f"https://127.0.0.1:{origin_port}/data")
            except httpx.ProxyError:
                pass
            else:
                assert refused.status_code == 403, (
                    f"suspended agent was still served: {refused.status_code}")
    finally:
        httpd.shutdown()
