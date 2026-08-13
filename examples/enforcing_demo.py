"""ENFORCED-mode demo: the plane actually performs the agent's actions.

It shows the whole point of the control plane:
  * the agent asks the plane to CALL an upstream (it never holds the credential);
  * an allowed read comes back with sensitive fields DLP-redacted;
  * a disallowed write is refused and the upstream is never touched;
  * a direct bypass attempt against the upstream fails (the agent has no key);
  * an over-threshold action needs human approval.

Just run it (after `make seed` and `make serve`):

    python examples/enforcing_demo.py

It self-provisions two demo agents via the admin API and boots the mock upstream
(examples/mock_upstream.py) on :9100 for you — no manual key copying needed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

import httpx  # noqa: E402

from agentguard_sdk import AgentGuardClient  # noqa: E402

URL = os.environ.get("AGENTGUARD_URL", "http://localhost:8080")
ADMIN_EMAIL = os.environ.get("AGENTGUARD_ADMIN_EMAIL", "admin@agentguard.local")
ADMIN_PASSWORD = os.environ.get("AGENTGUARD_ADMIN_PASSWORD", "admin")
UPSTREAM = "http://127.0.0.1:9100"

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")


def _die(msg: str) -> None:
    print(f"\n✗ {msg}")
    raise SystemExit(1)


def _start_upstream() -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "examples.mock_upstream:app", "--port", "9100"],
        cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        try:
            if httpx.get(f"{UPSTREAM}/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            time.sleep(0.25)
    return proc


def _admin_headers(http: httpx.Client) -> dict:
    try:
        r = http.post("/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    except httpx.HTTPError:
        _die(f"Could not reach the plane at {URL}. Is `make serve` running?")
    if r.status_code != 200:
        _die("Admin login failed. Set AGENTGUARD_ADMIN_PASSWORD if you changed it.")
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _provision_agent(http: httpx.Client, headers: dict, role_name: str) -> str:
    roles = http.get("/api/roles", headers=headers).json()
    role = next((x for x in roles if x["name"] == role_name), None)
    if not role:
        _die(f"Role '{role_name}' not found. Run `make seed` (or `agentguard seed`) first.")
    connectors = {c["name"] for c in http.get("/api/connectors", headers=headers).json()}
    if not {"crm", "payments"} <= connectors:
        _die("Connectors 'crm'/'payments' not found. Run `make seed` first.")
    agent = http.post("/api/agents", headers=headers,
                      json={"name": f"demo-{role_name}", "role_id": role["id"]}).json()
    return agent["api_key"]


def main() -> int:
    with httpx.Client(base_url=URL, timeout=10) as http:
        headers = _admin_headers(http)
        support_key = _provision_agent(http, headers, "customer-support-agent")
        billing_key = _provision_agent(http, headers, "billing-agent")

    upstream = _start_upstream()
    try:
        support = AgentGuardClient(URL, api_key=support_key)
        billing = AgentGuardClient(URL, api_key=billing_key)

        print("1) SupportBot reads customer 1042 THROUGH the plane (enforced):")
        r = support.execute("crm", "GET", "/customers/1042")
        print(f"   executed={r['executed']} status={r['status_code']}")
        print(f"   response the agent actually received: {r['response_body']}")
        if r["response_dlp_findings"]:
            kinds = ", ".join(f["detector"] for f in r["response_dlp_findings"])
            print(f"   -> DLP redacted from the response before the agent saw it: {kinds}")

        print("\n2) SupportBot tries to POST a write to the CRM connector (not allowed):")
        w = support.execute("crm", "POST", "/customers/1042", body={"tier": "hacked"})
        print(f"   executed={w['executed']} decision={w['decision']} — {w['reason']}")

        print("\n3) SupportBot tries to bypass the plane and hit the upstream directly:")
        direct = httpx.get(f"{UPSTREAM}/customers/1042", timeout=3)
        print(f"   upstream responded {direct.status_code}: {direct.text[:70]}")
        print("   (the agent has NO upstream credential — the plane holds it — so it is refused)")

        print("\n4) BillingBot issues a $250 refund THROUGH the plane (executed for real):")
        ok = billing.execute("payments", "POST", "/refunds",
                             body={"invoice": "inv_1", "amount": 250}, metadata={"amount": 250})
        print(f"   executed={ok['executed']} status={ok['status_code']} body={ok['response_body']}")

        print("\n5) BillingBot tries a $2,000 refund (over threshold -> human approval):")
        big = billing.execute("payments", "POST", "/refunds",
                              body={"invoice": "inv_2", "amount": 2000}, metadata={"amount": 2000})
        print(f"   executed={big['executed']} decision={big['decision']} "
              f"approval_id={big['approval_id']} — {big['reason']}")
        print("   (approve it in the console, then the agent re-calls "
              "execute(..., approval_id=<id>) to proceed)")

        support.close()
        billing.close()
        print("\n✓ Done. Every action above is in the audit ledger (console → Audit Ledger).")
        return 0
    finally:
        upstream.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
