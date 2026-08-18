# Changelog

Notable changes to AgentGuard. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [semantic versioning](https://semver.org/).

## [0.3.0] — unreleased

### Changed — BREAKING: the project is now `agentguard`, not `agentops`

`agentops` is an existing package on PyPI belonging to a different company in
this same market, so this project could never have been published under it.
Everything named after the project changed in one pass:

| Was | Now |
|---|---|
| `pip install agentops` | `pip install agentguard` |
| `import agentops` / `from agentops_sdk import …` | `import agentguard` / `from agentguard_sdk import …` |
| `AgentOpsClient` | `AgentGuardClient` |
| `AGENTOPS_*` environment variables | `AGENTGUARD_*` |
| `agentops serve` / `seed` / `verify` | `agentguard serve` / `seed` / `verify` |
| API keys prefixed `agentops_sk_` | `agentguard_sk_` |
| Prometheus metrics `agentops_*` | `agentguard_*` |
| Default DB `./agentops.db` | `./agentguard.db` |
| CA cert `agentops-ca.crt` | `agentguard-ca.crt` |
| Log/SIEM logger names `agentops.*` | `agentguard.*` |

**To upgrade:** rename your environment variables to the `AGENTGUARD_` prefix,
update imports, and reinstall (`pip install agentguard`). Existing API keys keep
working — they are validated by hash, and only the human-readable prefix on
newly issued keys changes. If you route logs to a SIEM by logger name, update
the `agentops.*` selectors to `agentguard.*`.

**Existing audit ledgers do not carry over.** The ledger's HMAC is
domain-separated by a constant that contains the project name, so the rename
invalidates historic records exactly the way rotating `SECRET_KEY` does (see
the README's "Rotating SECRET_KEY breaks the ledger chain" section). This is
deliberate and was done before any production ledger exists: re-HMACing a chain
under a new domain is indistinguishable from the forgery the chain exists to
detect. Archive `agentguard verify` output plus your anchor file first if you
have a chain worth retaining.

### Fixed

- **Negative amounts bypassed spending ceilings and approval thresholds**
  (high) — every amount bound was `amount > limit`, so against a policy with
  `max_amount: 5000` and `require_approval_over: 500`, an `amount` of `-9500`
  was ALLOWED outright while `+9500` was correctly denied: no ceiling, no
  human, and no risk score (which separately gated on `amount > 0`). Payment
  APIs that read a negative refund as a charge turn this into a transfer the
  ceiling exists to prevent. Negative amounts now take the same route the
  engine already prescribed for a malformed amount — human review — and the
  risk score measures exposure by magnitude.
- **Cross-tenant IDOR in SCIM provisioning** (critical) — every SCIM endpoint
  operated on the user table by raw primary key with no `org_id` scoping, behind
  a single deployment-wide bearer token. One tenant's IdP token could list,
  read, rewrite and deactivate users in *every* other tenant. All SCIM routes
  are now scoped to the org their token resolves to, and the token comparison
  uses `hmac.compare_digest`.
- **Stored XSS in the operator console** (high) — agent/role/connector names are
  interpolated into `onclick` handlers; the HTML escaper did not escape single
  quotes, so a crafted name broke out of the JS string and ran with the viewing
  operator's session (the console JWT lives in `localStorage`). Added a
  JS-string-then-HTML escaper and applied it at all 8 affected sites.
- **A slow webhook receiver blocked every governance decision** (high) — webhook
  delivery was synchronous inside `AuditLedger.append()`, which every
  authorization calls inline, so a degraded SIEM/Slack endpoint added its full
  latency to each decision. Delivery moved to a bounded background queue.
- **OIDC auto-provisioning could create org-less users** — a missing bootstrap
  org caused `org_id = None`, and `NULL == NULL` matching in the tenancy filter
  would let such users see each other's org-scoped data. Now refuses to
  provision instead.
- **`dependency-audit` CI job was auditing the wrong package** — it audited the
  installed environment, which contained the local package; under the old name
  that resolved against the *other* `agentops` project on PyPI and always
  passed. Now audits `requirements.txt`.

### Added

- Redis-backed circuit breaker, DLP detector cache and alert throttle
  (`AGENTGUARD_DISTRIBUTED_STATE_BACKEND=redis`), so these stay correct across
  multiple workers/replicas instead of being silently per-process.
- Dependency (`pip-audit`) and container (Trivy) vulnerability scanning in CI.
- Pagination on the approvals list endpoint, matching every other list endpoint.

### Documentation

- SDK docstrings now state which methods are **enforced mode** (the plane holds
  the credential) versus **advisory mode** (`guard()`/`@governed`/tool-router —
  the agent still performs the action and is trusted to ask first). The README
  already drew this distinction; the code did not.
- Roadmap corrected: three versions were simultaneously marked "(Current)", and
  SOC 2 / PCI DSS reporting were listed as unbuilt despite being implemented.

## [0.1.0] — earlier

Initial public release under the previous name. See `ROADMAP.md` for the
feature history of the v0.1.0 and v0.2.0 milestones.
