# AgentGuard Roadmap

## v0.1.0 — MVP (shipped)
- [x] RBAC policy engine with glob matching, deny-overrides, constraints
- [x] Enforced mode: plane-as-proxy for upstream credentials
- [x] DLP scanner with 14+ detectors, redaction, severity-based blocking
- [x] Hash-chained, append-only audit ledger with out-of-band anchoring
- [x] Human-in-the-loop approval workflow with TTL expiry
- [x] Operator console (single-page UI)
- [x] Python SDK with `guard()` context manager and `@governed` decorator
- [x] SQLite and PostgreSQL support
- [x] Docker Compose for production deployment
- [x] Full CRUD API for agents, roles, policies, connectors
- [x] Security middleware (CSP, XFO, HSTS, body limits)
- [x] Login rate limiting (brute-force protection)
- [x] Background approval expiry sweeper
- [x] Prometheus-format metrics endpoint
- [x] Alembic database migrations
- [x] Health and readiness endpoints

---

## v0.2.0 — Enterprise & Scale (shipped)

Delivered as **pluggable adapters**: each has a dependency-free default and
activates only when its optional extra is installed (`pip install
agentguard[enterprise]`), so the air-gap-friendly single-binary story is intact.

### Identity & authorization
- [x] Enterprise SSO via OpenID Connect (Okta, Azure AD, Google Workspace) —
      RS256 ID-token validation, auto-provisioning, domain allowlist
- [x] **SCIM 2.0** user provisioning (`/api/scim/v2/Users`) — create / get /
      list-with-filter / PUT / PATCH-deactivate / delete, bearer-auth'd
- [x] **ABAC** — attribute-based conditions (`subject.*`, `resource.*`, `env.*`)
      with eq/ne/in/gt/glob/exists operators; subject/env attributes are
      server-set and unspoofable
- [x] **Policy-as-code** — delegate the RBAC verdict to **OPA (Rego)** or
      **Cedar** over HTTP; AgentGuard still enforces DLP/quota/approvals/ledger;
      fail-closed by default

### Protocol & connector support
- [x] **Message brokers** — governed Kafka publish (`/gateway/publish`): policy
      + DLP + ledger before a message hits a topic; RabbitMQ/SQS connector kinds
      recognized (producers pluggable)
- [x] **WebSocket** — the transparent proxy governs the WS handshake by policy
      before the connection is established, then tunnels frames
- [ ] **gRPC / Protobuf** and direct DB wire protocols (pgwire/MySQL) — connector
      kinds reserved; full wire interception is the remaining proxy work

### Scale & performance
- [x] **Redis-backed rate/quota** — sorted-set sliding window for sub-ms counts
      across horizontally scaled gateway nodes; auto-falls-back to the DB backend
- [x] Cached ledger integrity check (incremental verified-prefix) so the
      dashboard no longer re-walks the whole chain per load

### Guardrails & DLP
- [x] **LLM-native security** — prompt-injection / jailbreak / tool-abuse
      detectors, alerted and egress-blocked like any DLP finding
- [x] **ML DLP** — optional Microsoft Presidio provider for context-aware PII
      layered on the regex core

### Audit & observability
- [x] **Distributed anchoring** — pluggable backends: local file (default),
      Rekor-style transparency log, and RFC-3161 TSA timestamp tokens; plus a
      periodic full re-verify
- [x] **OpenTelemetry** — end-to-end spans across authorize → proxy → upstream
      with W3C trace-context propagation (no-op unless enabled + installed)
- [x] Audit export (CSV / JSON Lines), Prometheus `/metrics`, SIEM webhook

---

## v0.3.0 — Adaptive & Intelligent Governance (current)

### Risk & anomaly
- [x] **Adaptive risk scoring** — transparent 0–100 score per decision from DLP
      severity, egress, amount, resource/action novelty, off-hours, and volume
      z-score; exposed in the API/SDK and every explainable via its factor list
- [x] **Behavioral baselines** — per-agent norms computed from the agent's own
      ledger history (no separate feature store)
- [x] **Adaptive step-up** — above a configurable score, an ALLOW is escalated
      to human approval automatically (dual control without per-case policies)
- [x] **Risk alerts** — high-scoring actions raise a `high_risk` alert
- [x] Agent reputation signal (denial-ratio / volume surge) folded into risk

### Incident response
- [x] **Emergency kill switch** — org-level containment freezes the entire fleet
      in one toggle (ledger-recorded); superadmin can contain any tenant
- [x] LLM prompt-injection / jailbreak detection with alerting (v0.2)
- [x] Automated containment — auto-suspend after repeated exfiltration (v0.1)

### Policy & agent intelligence
- [x] **Policy analysis** — per-role detection of shadowed allows, redundant /
      duplicate rules, overly-broad grants, never-matched policies, and denial
      hotspots (candidate gaps) from the audit history
- [x] **Agent reputation** — rolling 0–100 trust score per agent from its ledger
      + alert history (denial ratio, DLP rate, abuse alerts, mean risk), banded
- [x] **Risk persisted on the ledger** — score + factors recorded per decision
      (excluded from the hash so integrity is unaffected), queryable & analytics-ready
- [x] **Signed webhooks** — HMAC-SHA256 signatures on alert + SIEM deliveries

### Still planned
- [x] **Policy recommendations** — candidate allow rules generated from recurring
      default-deny gaps (per-id resources generalized, confidence-scored,
      one-click adopt); intentional deny/DLP blocks are never recommended away
- [x] **Safe-apply impact preview** — dry-run a candidate policy against real
      denied traffic before adopting it (flags sensitive/DLP blast radius)
- [x] **Policy versioning + rollback** — every create/update/delete snapshotted;
      view history and restore any prior version
- [x] **Custom DLP detectors** — operator-defined, org-scoped regex detectors
      merged with the built-ins (no fork); `regex` ABAC operator
- [x] **Per-policy risk step-up** — a policy overrides the global step-up
      threshold via `conditions.risk_step_up` (tighten sensitive rules; 0 opts out)
- [x] **Time-bound containment** — the kill switch takes an optional duration and
      auto-lifts when the window elapses (lazy at the gateway + background sweeper)
- [x] **Upstream resilience** — bounded retries (transient blips / 5xx) + a
      per-connector circuit breaker that fails fast during a sustained outage
      instead of hanging every agent behind a dead dependency
- [x] **Approval notifications** — a pending approval POSTs a signed webhook
      (Slack-formatted for Slack URLs) so a human knows a decision is waiting
- [x] **Alert flood control** — webhook dedup throttles repeat notifications per
      (org, kind, agent); the alert is always still recorded in the DB
- [x] **Hardening pass (adversarial review)** — fixed a cross-tenant audit-data
      leak in policy analytics (org_id scoping), ReDoS on operator regex
      (subprocess-bounded validation + `/test`), fail-closed parsing of malformed
      policy conditions, single-use approvals restored when a post-claim deny
      blocks execution, unique policy-version numbering, and CAS on containment
      auto-resume
- [ ] Real-time WebSocket streaming of audit events
- [ ] Agent versioning / deployment tracking; A/B (canary) policy testing

### Compliance
- [x] **SOC 2 evidence collection automation** — `compliance.py` maps control
      families to concrete ledger evidence and reports coverage honestly,
      flagging controls with no evidence as gaps rather than passing them
- [x] **PCI DSS audit trail compliance reporting** — same engine; `soc2`,
      `gdpr`, `hipaa` and `pci_dss` frameworks, exposed at
      `/api/compliance/{frameworks,report,report.md,summary}`
- [ ] GDPR data subject access request (DSAR) support — the GDPR *control
      mapping* exists; per-subject access/erasure requests do not

---

## Contributing

We welcome contributions! Please see `CONTRIBUTING.md` for guidelines on how to propose features and submit pull requests.
