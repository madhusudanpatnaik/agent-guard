"""Proves the transparent proxy governs an UNMODIFIED HTTP client — no SDK, no bypass."""

import http.server
import socket
import ssl
import threading
import time

import httpx
import pytest


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _OriginHandler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send(200, b'{"origin":"reached"}')

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        self._send(200, b'{"origin":"posted"}')

    def log_message(self, *args):  # silence
        pass


@pytest.fixture
def origin():
    port = _free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), _OriginHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


@pytest.fixture
def proxy_port():
    from agentops.proxy import serve_proxy
    port = _free_port()
    threading.Thread(target=lambda: serve_proxy("127.0.0.1", port), daemon=True).start()
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return port


def _agent_with_policy(client, admin_headers, resource, actions):
    role = client.post("/api/roles", json={"name": "proxied"}, headers=admin_headers).json()
    if resource:
        client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers,
                    json={"effect": "allow", "resource": resource, "actions": actions})
    agent = client.post("/api/agents", json={"name": "ProxyBot", "role_id": role["id"]},
                        headers=admin_headers).json()
    return agent["api_key"]


def _proxied_client(key, proxy_port):
    return httpx.Client(proxy=f"http://agent:{key}@127.0.0.1:{proxy_port}", timeout=10)


def test_allowed_request_is_proxied_to_origin(client, admin_headers, origin, proxy_port):
    key = _agent_with_policy(client, admin_headers, "http:127.0.0.1:**", ["http.get"])
    with _proxied_client(key, proxy_port) as c:
        r = c.get(f"http://127.0.0.1:{origin}/data")
    assert r.status_code == 200
    assert r.json()["origin"] == "reached"   # unmodified client, governed + forwarded


def test_policy_denied_request_is_blocked(client, admin_headers, origin, proxy_port):
    # Agent has NO policy -> default-deny.
    key = _agent_with_policy(client, admin_headers, None, [])
    with _proxied_client(key, proxy_port) as c:
        r = c.get(f"http://127.0.0.1:{origin}/data")
    assert r.status_code == 403
    assert r.json()["agentops"] == "blocked"   # origin never reached


def test_dlp_blocks_exfiltration_through_proxy(client, admin_headers, origin, proxy_port):
    key = _agent_with_policy(client, admin_headers, "http:127.0.0.1:**", ["http.post"])
    with _proxied_client(key, proxy_port) as c:
        r = c.post(f"http://127.0.0.1:{origin}/upload",
                   json={"data": "AKIAIOSFODNN7EXAMPLE"})
    assert r.status_code == 403
    assert "exfiltration" in r.json()["reason"].lower()


def test_missing_api_key_is_rejected(client, admin_headers, origin, proxy_port):
    # Proxy without credentials -> 407 Proxy Authentication Required.
    with httpx.Client(proxy=f"http://127.0.0.1:{proxy_port}", timeout=10) as c:
        try:
            r = c.get(f"http://127.0.0.1:{origin}/data")
            assert r.status_code == 407
        except httpx.ProxyError:
            pass  # some httpx versions raise on 407 — either way, not allowed


def test_websocket_upgrade_is_governed_by_policy(client, admin_headers, origin, proxy_port):
    # An agent with NO ws policy must have its WebSocket handshake denied by the
    # proxy BEFORE any upstream socket is opened (default-deny on ws.connect).
    import socket

    key = _agent_with_policy(client, admin_headers, None, [])  # no policy
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    try:
        handshake = (
            f"GET http://127.0.0.1:{origin}/ws HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin}\r\n"
            f"Proxy-Authorization: Bearer {key}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        raw.sendall(handshake.encode())
        resp = raw.recv(4096).decode("latin-1", "replace")
    finally:
        raw.close()
    assert "403" in resp.split("\r\n", 1)[0]         # blocked at the handshake
    assert "blocked" in resp.lower()


# --------------------------------------------------------------------------- #
# HTTPS via TLS interception — the real-traffic case
# --------------------------------------------------------------------------- #

def _self_signed(tmp_path):
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    cf = tmp_path / "origin.crt"
    kf = tmp_path / "origin.key"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return str(cf), str(kf)


@pytest.fixture
def tls_origin(tmp_path):
    certfile, keyfile = _self_signed(tmp_path)
    port = _free_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _OriginHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield port
    httpd.shutdown()


def test_https_body_is_inspected_and_governed(client, admin_headers, tls_origin, proxy_port,
                                              monkeypatch):
    import agentops.proxy as proxymod
    from agentops.config import get_settings
    # The demo origin is self-signed, so don't verify it (production verifies).
    monkeypatch.setattr(get_settings(), "proxy_verify_upstream_tls", False)

    key = _agent_with_policy(client, admin_headers, "https:127.0.0.1**",
                             ["http.connect", "http.get", "http.post"])
    ca_ctx = ssl.create_default_context(cafile=str(proxymod._CA.cert_path))  # trust AgentOps CA
    with httpx.Client(proxy=f"http://agent:{key}@127.0.0.1:{proxy_port}",
                      verify=ca_ctx, timeout=15) as c:
        # Allowed HTTPS GET is decrypted, governed, and forwarded.
        r = c.get(f"https://127.0.0.1:{tls_origin}/data")
        assert r.status_code == 200
        assert r.json()["origin"] == "reached"

        # A secret inside an HTTPS request body is caught — the proxy SEES the plaintext.
        blocked = c.post(f"https://127.0.0.1:{tls_origin}/upload",
                         json={"payload": "AKIAIOSFODNN7EXAMPLE"})
    assert blocked.status_code == 403
    assert "exfiltration" in blocked.json()["reason"].lower()
