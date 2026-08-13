"""AgentGuard transparent-proxy demo — govern an agent that uses NO SDK.

The agent below makes ordinary ``httpx`` calls. It has zero AgentGuard code — the
only thing that changed is its ``HTTP_PROXY`` (which in production the operator/
container sets, and a network egress rule enforces). Every call is still
policy-checked, DLP-scanned, logged, and blockable, and the agent has no way to
opt out.

Run it (after `make seed` and `make serve`):

    python examples/proxy_demo.py

It provisions an agent via the admin API and starts the proxy + a local origin
in-process for you.
"""

from __future__ import annotations

import http.server
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

import httpx  # noqa: E402

URL = os.environ.get("AGENTGUARD_URL", "http://localhost:8080")
ADMIN_EMAIL = os.environ.get("AGENTGUARD_ADMIN_EMAIL", "admin@agentguard.local")
ADMIN_PASSWORD = os.environ.get("AGENTGUARD_ADMIN_PASSWORD", "admin")

BOLD, DIM, GREEN, RED, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[0m"


def _die(msg: str) -> None:
    print(f"\n{RED}✗ {msg}{RESET}")
    raise SystemExit(1)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Origin(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send(200, b'{"data":"real business data"}')

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        self._send(200, b'{"ok":true}')

    def log_message(self, *a):
        pass


def _provision(http_client: httpx.Client, origin_port: int) -> str:
    r = http_client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    if r.status_code != 200:
        _die(f"admin login failed at {URL} — is `make serve` running?")
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    # Idempotent role (re-runs must not 409); policies are re-scoped per random port.
    existing = next((x for x in http_client.get("/api/roles", headers=h).json()
                     if x["name"] == "proxied-agent"), None)
    rid = existing["id"] if existing else http_client.post(
        "/api/roles", headers=h, json={"name": "proxied-agent"}).json()["id"]
    # May GET the /public area, and may POST there too (to show DLP still blocks secrets).
    http_client.post(f"/api/roles/{rid}/policies", headers=h, json={
        "effect": "allow", "resource": f"http:127.0.0.1:{origin_port}/public/**",
        "actions": ["http.get", "http.post"]})
    return http_client.post("/api/agents", headers=h,
                            json={"name": "UnmodifiedAgent", "role_id": rid}).json()["api_key"]


def main() -> int:
    origin_port = _free_port()
    proxy_port = _free_port()

    with httpx.Client(base_url=URL, timeout=10, trust_env=False) as admin:
        key = _provision(admin, origin_port)

    # Start a local origin + the AgentGuard proxy, both in-process.
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    from agentguard.proxy import serve_proxy
    threading.Thread(target=serve_proxy, args=("127.0.0.1", proxy_port),
                     daemon=True).start()
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", proxy_port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)

    print(f"{BOLD}The agent uses a plain httpx client — no AgentGuard SDK — with only "
          f"HTTP_PROXY set.{RESET}")
    print(f"{DIM}Its egress is routed through the AgentGuard proxy on :{proxy_port}.{RESET}\n")

    # NOTE: nothing below imports agentguard — this is a vanilla HTTP client.
    agent_http = httpx.Client(proxy=f"http://agent:{key}@127.0.0.1:{proxy_port}", timeout=10)

    def call(desc, method, path, **kw):
        url = f"http://127.0.0.1:{origin_port}{path}"
        try:
            r = agent_http.request(method, url, **kw)
        except httpx.HTTPError as e:
            print(f"  {RED}✗{RESET} {desc}: proxy error {e}")
            return
        if r.status_code == 200:
            print(f"  {GREEN}✓ ALLOWED{RESET}  {desc} → origin returned {r.json()}")
        else:
            body = r.json()
            print(f"  {RED}✗ BLOCKED{RESET}  {desc} → {body.get('reason', body)}")

    call("GET /public/report (in policy)", "GET", "/public/report")
    call("GET /admin/secrets (NOT in policy)", "GET", "/admin/secrets")
    call("POST /public/upload with an AWS key in the body (DLP)", "POST", "/public/upload",
         json={"note": "here is AKIAIOSFODNN7EXAMPLE"})

    agent_http.close()
    srv.shutdown()
    print(f"\n{BOLD}The agent could not bypass governance — it never had a choice.{RESET}")
    print(f"{DIM}Every call above is in the audit ledger (console → Audit Ledger).{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
