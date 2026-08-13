"""AgentGuard — client pitch demo.

A narrated, end-to-end walkthrough you can run live in front of a buyer. It uses
the REAL control plane (no mocked decisions) to show, for a fictional bank
("Northwind Financial") deploying AI agents, exactly what governance prevents:

  1. an AI support agent reads a customer record — sensitive PII is redacted
     out of what the agent (and therefore the LLM / prompt logs) ever sees;
  2. the same agent is blocked from modifying that record (least privilege);
  3. the agent physically cannot exfiltrate data — it never holds a credential;
  4. a billing agent auto-issues a small refund within policy;
  5. a large refund is held for human approval (dual control);
  6. a compliance officer approves it and the agent proceeds;
  7. an oversized refund is denied outright by the spending ceiling;
  8. every decision lands in a cryptographically tamper-evident audit ledger.

Run it (after `make seed` and `make serve`):

    python examples/pitch_demo.py

It self-provisions the two demo agents via the admin API and boots the mock
upstream ("Northwind core banking API") for you — nothing to copy by hand.
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

BOLD, DIM, GREEN, RED, YELLOW, CYAN, RESET = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[0m"
)


def _die(msg: str) -> None:
    print(f"\n{RED}✗ {msg}{RESET}")
    raise SystemExit(1)


def _rule(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 74}{RESET}")
    print(f"{BOLD}{CYAN}{title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 74}{RESET}")


def _step(n: int, ask: str) -> None:
    print(f"\n{BOLD}{n}. {ask}{RESET}")


def _outcome(allowed: bool, decision: str, prevented: str) -> None:
    badge = f"{GREEN}✓ {decision.upper()}{RESET}" if allowed else f"{RED}✗ {decision.upper()}{RESET}"
    print(f"   plane → {badge}")
    print(f"   {DIM}business impact:{RESET} {prevented}")


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


def _admin(http: httpx.Client) -> dict:
    try:
        r = http.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    except httpx.HTTPError:
        _die(f"Could not reach the control plane at {URL}. Is `make serve` running?")
    if r.status_code != 200:
        _die("Admin login failed. Set AGENTGUARD_ADMIN_PASSWORD if you changed it.")
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _provision(http: httpx.Client, headers: dict, role_name: str, label: str) -> str:
    role = next((x for x in http.get("/api/roles", headers=headers).json()
                 if x["name"] == role_name), None)
    if not role:
        _die(f"Role '{role_name}' not found. Run `make seed` (or `agentguard seed`) first.")
    connectors = {c["name"] for c in http.get("/api/connectors", headers=headers).json()}
    if not {"crm", "payments"} <= connectors:
        _die("Demo connectors 'crm'/'payments' not found. Run `make seed` first.")
    agent = http.post("/api/agents", headers=headers,
                      json={"name": label, "role_id": role["id"]}).json()
    return agent["api_key"]


def main() -> int:
    print(f"{BOLD}AgentGuard — governance for autonomous AI agents{RESET}")
    print(f"{DIM}Scenario: Northwind Financial deploys two AI agents into production.{RESET}")

    with httpx.Client(base_url=URL, timeout=10) as http:
        headers = _admin(http)
        support_key = _provision(http, headers, "customer-support-agent", "NorthwindSupportGPT")
        billing_key = _provision(http, headers, "billing-agent", "NorthwindPayBot")
        analyst_key = _provision(http, headers, "data-analyst-agent", "NorthwindAnalyticsGPT")

        upstream = _start_upstream()
        try:
            support = AgentGuardClient(URL, api_key=support_key)
            billing = AgentGuardClient(URL, api_key=billing_key)

            # ---- Support agent -------------------------------------------------
            _rule("AI SUPPORT AGENT  ·  role: customer-support (read-only)")

            _step(1, "SupportGPT looks up customer #1042 to answer a ticket")
            r = support.execute("crm", "GET", "/customers/1042")
            leaked = ", ".join(f["detector"] for f in r["response_dlp_findings"]) or "none"
            print(f"   {DIM}data the agent actually received:{RESET} {r['response_body']}")
            _outcome(r["executed"], "allow",
                     f"PII redacted before the agent/LLM saw it ({leaked}) — "
                     "no customer data leaks into prompts, logs, or the model provider.")

            _step(2, "SupportGPT tries to CHANGE the customer's account tier")
            w = support.execute("crm", "POST", "/customers/1042", body={"tier": "vip"})
            _outcome(w["executed"], w["decision"],
                     "least privilege — a support agent cannot mutate records it may only read.")

            _step(3, "A prompt-injected SupportGPT tries to exfiltrate the data directly")
            direct = httpx.get(f"{UPSTREAM}/customers/1042", timeout=3)
            _outcome(direct.status_code == 200 and False, f"blocked ({direct.status_code})",
                     "the agent holds no upstream credential — the plane does — so it "
                     "cannot go around governance even if the model is hijacked.")

            # ---- Billing agent -------------------------------------------------
            _rule("AI BILLING AGENT  ·  role: billing (refunds, $5k ceiling, $500 review)")

            _step(4, "PayBot auto-issues a $250 goodwill refund")
            ok = billing.execute("payments", "POST", "/refunds",
                                 body={"invoice": "INV-8801", "amount": 250}, metadata={"amount": 250})
            _outcome(ok["executed"], "allow",
                     f"straight-through automation within policy → {ok['response_body']}")

            _step(5, "PayBot attempts a $2,000 refund (above the $500 review line)")
            big = billing.execute("payments", "POST", "/refunds",
                                  body={"invoice": "INV-8802", "amount": 2000}, metadata={"amount": 2000})
            _outcome(big["executed"], big["decision"],
                     "dual control — a large payout is held for a human, not auto-approved.")
            approval_id = big["approval_id"]

            _step(6, f"Compliance officer approves request #{approval_id} in the console")
            http.post(f"/api/approvals/{approval_id}/resolve", headers=headers,
                      json={"approve": True, "note": "verified with customer — approved"})
            done = billing.execute("payments", "POST", "/refunds",
                                   body={"invoice": "INV-8802", "amount": 2000},
                                   metadata={"amount": 2000}, approval_id=approval_id)
            _outcome(done["executed"], "allow",
                     f"the agent proceeds only AFTER human sign-off → {done['response_body']}")

            _step(7, "PayBot attempts a $9,500 refund (above the $5,000 ceiling)")
            huge = billing.execute("payments", "POST", "/refunds",
                                   body={"invoice": "INV-8803", "amount": 9500}, metadata={"amount": 9500})
            _outcome(huge["executed"], huge["decision"],
                     "hard spending ceiling — no human can even be asked; it is refused.")

            # ---- Analytics agent (governed SQL) --------------------------------
            _rule("AI ANALYTICS AGENT  ·  role: data-analyst (read-only SQL)")

            analyst = AgentGuardClient(URL, api_key=analyst_key)
            _step(8, "AnalyticsGPT queries the data warehouse for top VIP customers")
            q = analyst.query(
                "warehouse",
                "SELECT name, email, ssn, lifetime_value FROM customers "
                "WHERE tier = :t ORDER BY lifetime_value DESC",
                params={"t": "vip"},
            )
            redacted = ", ".join(f["detector"] for f in q["response_dlp_findings"]) or "none"
            print(f"   {DIM}rows the agent received:{RESET} {q['rows']}")
            _outcome(q["executed"], "allow",
                     f"the plane ran the SQL (agent never sees the DB credentials) and "
                     f"redacted {redacted} from every row.")

            _step(9, "AnalyticsGPT tries to DELETE from the warehouse")
            bad = analyst.query("warehouse", "DELETE FROM customers")
            _outcome(bad["executed"], "deny",
                     f"read-only enforcement — {bad['error']}")

            support.close()
            billing.close()
            analyst.close()

            # ---- Audit posture -------------------------------------------------
            _rule("AUDIT & COMPLIANCE")
            chain = http.get("/api/audit/verify", headers=headers).json()
            head = http.get("/api/audit/head", headers=headers).json()
            print("   Every decision above is in an append-only, hash-chained ledger.")
            print(f"   integrity check: {GREEN if chain['valid'] else RED}"
                  f"{chain['detail']}{RESET}  ·  {head['count']} records  ·  "
                  f"head {head['hash'][:16]}…")
            print(f"   {DIM}Tamper with any historical row and this check fails — "
                  f"auditor-ready, non-repudiable evidence.{RESET}")

            _rule("THE PITCH")
            print(f"""  In one demo the plane {GREEN}prevented{RESET}:
     • customer PII leaking into an LLM / provider / logs        (privacy, GDPR)
     • an agent modifying data beyond its role                   (least privilege)
     • data exfiltration even under prompt injection             (containment)
     • an unauthorized large payout                              (financial control)
     • raw PII leaving the data warehouse over SQL               (data governance)
   …while {GREEN}allowing{RESET} safe automation to run straight through, and recording
   {BOLD}everything{RESET} in tamper-evident, exportable audit evidence.

  {BOLD}AgentGuard is the firewall + identity layer every enterprise needs before it
  lets AI agents touch production.{RESET}
""")
            return 0
        finally:
            upstream.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
