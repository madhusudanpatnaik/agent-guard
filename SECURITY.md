# Security Policy

agent-guard is security infrastructure — it enforces policy, isolates
credentials and records a tamper-evident audit ledger. A flaw here is a flaw in
someone's control plane, so reports are taken seriously and triaged quickly.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

**Please do not open a public issue for a security bug.**

Use GitHub's private vulnerability reporting, which is enabled on this
repository:

1. Go to the [Security tab](https://github.com/madhusudanpatnaik/agent-guard/security)
2. Click **Report a vulnerability**
3. Describe the issue, affected version, and impact

This creates a private advisory visible only to you and the maintainer.

### What to include

- Affected component (policy engine, DLP, credential broker, audit ledger, SDK)
- Version or commit SHA
- Reproduction steps, ideally a minimal proof of concept
- Impact — what an attacker gains, and what access they need to start

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix or mitigation plan | within 30 days for High/Critical |

These are targets for a project maintained by one person, not a contractual SLA.

## Scope

**In scope** — policy bypass (RBAC/ABAC), DLP exfiltration bypass, credential
leakage from the broker, audit-ledger tampering or forgery, approval-flow
bypass, privilege escalation between agents or tenants, and authentication or
session flaws in the API.

**Out of scope** — findings that require an already-compromised host or
maintainer-level credentials; denial of service from unbounded self-inflicted
load; vulnerabilities in third-party dependencies without a demonstrated
exploit path through this project; and results from automated scanners
submitted without a working proof of concept.

## Disclosure

Coordinated disclosure. Report privately, and once a fix ships a GitHub
Security Advisory will be published crediting you unless you prefer otherwise.
Please give a reasonable window before public discussion.

## Safe harbour

Good-faith research under this policy is welcome, and no legal action will be
pursued for it. Test only against your own deployment — never against another
party's data or infrastructure.
