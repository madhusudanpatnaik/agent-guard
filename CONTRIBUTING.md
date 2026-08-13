# Contributing to agent-guard

Thanks for taking an interest. This document covers the setup, the checks CI
runs, and what a reviewable pull request looks like.

> **Security bugs do not belong in issues or pull requests.**
> Follow [SECURITY.md](SECURITY.md) instead.

## Setup

**Prerequisites:** Python 3.11 or 3.12 (CI tests both), Docker for the
container and database targets.

```bash
make install          # install the package plus dev extras
cp .env.example .env  # then fill in the values
make migrate          # apply Alembic migrations
make seed             # load sample data
make serve            # run the control plane locally
```

## The checks

Run this before pushing — it is the same set CI enforces:

```bash
make ci
```

Individually:

| Command | What it runs |
|---|---|
| `make lint` | `ruff check agentguard sdk examples tests scripts` |
| `make typecheck` | `mypy agentguard --ignore-missing-imports` |
| `make test` | pytest |
| `make cover` | pytest with coverage |
| `make verify` | full verification pass |

CI additionally builds the Docker image and scans it with Trivy for
CRITICAL/HIGH findings, uploading results to GitHub code scanning.

## Pull requests

- **Branch from `main`** and keep the change focused — one concern per PR.
- **Add tests.** This is a policy-enforcement system; a change to policy
  evaluation, DLP matching, or the audit ledger without a test proving the new
  behaviour will be asked for one.
- **Never weaken a default.** If a change makes something more permissive by
  default, say so explicitly in the PR description and explain why.
- **Migrations:** schema changes need an Alembic revision via
  `make migration`. Do not hand-edit existing revisions that have shipped.
- **Keep `make ci` green.** A red PR will not be reviewed until it is green.

## Commit messages

Short imperative subject, then a body explaining *why* rather than *what* — the
diff already shows what changed.

```
Reject wildcard resource patterns in ABAC rules

A rule with resource "*" silently matched every tenant's objects because
the matcher short-circuited before the tenant check. Narrow the wildcard
to within-tenant and add a regression test.
```

## Reporting bugs

Open an issue using the bug report template. A reproduction — even a rough one
— is worth more than a detailed prose description.

## Code layout

| Path | Contents |
|---|---|
| `agentguard/` | Control-plane package (policy, DLP, credentials, ledger) |
| `sdk/` | Client SDK |
| `examples/` | Runnable usage examples |
| `tests/` | Test suite |
| `alembic/` | Database migrations |
| `scripts/` | Operational scripts |

> **Note:** the Python package is `agentguard/` while the repository is
> `agent-guard`. The package name is kept for import stability; renaming it
> would break every existing import.
