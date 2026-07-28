"""Governed message-broker publishing (Kafka / RabbitMQ / SQS).

Extends the "the plane holds the credential, the agent never does" model from
HTTP and SQL to event streams. An operator registers a ``kafka`` (or other
broker) connector whose vaulted secret is the broker connection config; an agent
asks the plane to publish a message to a topic. The plane:

  1. authorizes it against RBAC/ABAC policy (resource ``broker:<connector>:<topic>``,
     action ``broker.publish``) — including quota, rate, approval, and ABAC;
  2. **DLP-scans the message** so secrets/PII can't be exfiltrated onto a topic;
  3. publishes via the vaulted broker client (import-guarded per broker kind);
  4. records the publish (and its DLP findings) to the tamper-evident ledger.

The broker client libraries are optional dependencies: the code imports them
lazily and a missing library yields a clear error rather than an import-time
crash. A ``producer`` can be injected for testing without a live broker.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit.ledger import AuditLedger
from .gateway_service import _claim_approval, _restore_approval, authorize_action
from .models import Agent, Approval, AuditRecord, Connector, Decision
from .policy.engine import ActionRequest, PolicyDecision
from .utils import build_preview, payload_fingerprint
from .vault import decrypt_secret


@dataclass
class PublishResult:
    executed: bool
    decision: PolicyDecision
    audit_record: AuditRecord
    approval: Approval | None = None
    error: str | None = None
    request_dlp_findings: list[dict] = field(default_factory=list)


class _Producer:
    """Minimal produce interface so backends and test doubles are interchangeable."""

    def send(self, topic: str, value: bytes, key: bytes | None = None) -> None:
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _build_producer(connector: Connector) -> _Producer:
    """Construct a broker producer from the vaulted connector secret.

    The secret is a small config string; for Kafka it is the bootstrap servers
    (optionally ``host:port,host:port``). Import-guarded so the dependency is
    only needed when a broker connector is actually used.
    """
    dsn = decrypt_secret(connector.auth_secret_encrypted)
    kind = connector.kind.lower()
    if kind == "kafka":
        try:
            from kafka import KafkaProducer
        except ImportError as exc:
            raise ValueError("kafka connector requires the 'kafka-python' package") from exc

        client = KafkaProducer(bootstrap_servers=dsn.split(","))

        class _KafkaProducer(_Producer):
            def send(self, topic, value, key=None):
                client.send(topic, value=value, key=key)
                client.flush()

            def close(self):
                client.close()

        return _KafkaProducer()
    raise ValueError(f"unsupported broker kind '{connector.kind}'")


def publish_message(
    db: Session,
    agent: Agent,
    *,
    connector_name: str,
    topic: str,
    message,
    key: str | None = None,
    metadata: dict | None = None,
    approval_id: int | None = None,
    producer: _Producer | None = None,
) -> PublishResult:
    """Authorize and (if permitted) publish a message to a broker topic."""
    connector = db.scalar(
        select(Connector).where(
            Connector.name == connector_name, Connector.org_id == agent.org_id
        )
    )
    if not connector or not connector.enabled:
        raise ValueError(f"unknown or disabled connector '{connector_name}'")
    if connector.kind.lower() not in {"kafka", "rabbitmq", "sqs"}:
        raise ValueError(f"connector '{connector_name}' is not a broker connector")

    resource = f"broker:{connector_name}:{topic}"
    action_type = "broker.publish"
    req = ActionRequest(action_type=action_type, resource=resource,
                        payload=message, metadata=metadata or {})

    claimed = _claim_approval(db, approval_id, agent, resource, action_type)
    auth = authorize_action(db, agent, req, pre_approved=claimed)
    req_findings = auth.decision.dlp.findings_as_dicts() if auth.decision.dlp else []
    if auth.decision.decision != Decision.ALLOW:
        if claimed:  # action won't run — don't burn the human sign-off
            _restore_approval(db, approval_id, agent, resource, action_type)
        return PublishResult(executed=False, decision=auth.decision,
                             audit_record=auth.audit_record, approval=auth.approval,
                             request_dlp_findings=req_findings)

    ledger = AuditLedger(db)
    own_producer = producer is None
    try:
        producer = producer or _build_producer(connector)
        payload = message if isinstance(message, (bytes, bytearray)) else str(message).encode()
        producer.send(topic, value=bytes(payload), key=key.encode() if key else None)
    except Exception as exc:  # noqa: BLE001 — broker/library failure
        ledger.append(
            agent_id=agent.id, agent_name=agent.name,
            role_name=agent.role.name if agent.role else "",
            action_type=f"{action_type}.result", resource=resource,
            decision=Decision.DENY, reason=f"Publish failed: {exc}",
            billable=False, org_id=agent.org_id,
        )
        return PublishResult(executed=False, decision=auth.decision,
                             audit_record=auth.audit_record, error=str(exc),
                             request_dlp_findings=req_findings)
    finally:
        if own_producer and producer is not None:
            producer.close()

    ledger.append(
        agent_id=agent.id, agent_name=agent.name,
        role_name=agent.role.name if agent.role else "",
        action_type=f"{action_type}.result", resource=resource,
        decision=Decision.ALLOW, reason=f"Published to {resource}",
        payload_hash=payload_fingerprint(message),
        payload_preview=build_preview(topic), billable=False, org_id=agent.org_id,
    )
    return PublishResult(executed=True, decision=auth.decision,
                         audit_record=auth.audit_record, request_dlp_findings=req_findings)
