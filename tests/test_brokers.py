"""Tests for governed message-broker publishing."""

import pytest

from agentops.brokers import publish_message
from agentops.brokers import _Producer


class FakeProducer(_Producer):
    def __init__(self):
        self.sent = []
        self.closed = False

    def send(self, topic, value, key=None):
        self.sent.append((topic, value, key))

    def close(self):
        self.closed = True


def _broker_agent(client, admin_headers, *, actions, dsn="localhost:9092"):
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "events", "kind": "kafka", "base_url": "kafka-cluster",
        "auth_type": "none", "auth_secret": dsn})
    role = client.post("/api/roles", headers=admin_headers, json={"name": "publisher"}).json()
    rid = role["id"]
    if actions:
        client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
            "effect": "allow", "resource": "broker:events:*", "actions": actions})
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "PubBot", "role_id": rid}).json()
    return agent


def _agent_orm(db, api_key_prefix):
    from sqlalchemy import select
    from agentops.models import Agent
    return db.scalar(select(Agent).where(Agent.api_key_prefix == api_key_prefix))


def test_publish_allowed_sends_to_topic(client, admin_headers, db):
    agent = _broker_agent(client, admin_headers, actions=["broker.publish"])
    a = _agent_orm(db, agent["api_key_prefix"])
    fake = FakeProducer()
    res = publish_message(db, a, connector_name="events", topic="orders.created",
                          message={"order": 1}, producer=fake)
    assert res.executed is True
    assert fake.sent and fake.sent[0][0] == "orders.created"


def test_publish_denied_by_policy_never_sends(client, admin_headers, db):
    agent = _broker_agent(client, admin_headers, actions=None)  # no policy -> default-deny
    a = _agent_orm(db, agent["api_key_prefix"])
    fake = FakeProducer()
    res = publish_message(db, a, connector_name="events", topic="orders.created",
                          message={"order": 1}, producer=fake)
    assert res.executed is False
    assert res.decision.decision == "deny"
    assert fake.sent == []  # broker never touched


def test_publish_blocks_secret_exfiltration(client, admin_headers, db):
    agent = _broker_agent(client, admin_headers, actions=["broker.publish"])
    a = _agent_orm(db, agent["api_key_prefix"])
    fake = FakeProducer()
    res = publish_message(db, a, connector_name="events", topic="leak",
                          message={"k": "AKIAIOSFODNN7EXAMPLE"}, producer=fake)
    # broker.publish is egress -> DLP blocks the secret before it reaches Kafka.
    assert res.executed is False
    assert res.decision.decision == "deny"
    assert fake.sent == []


def test_publish_non_broker_connector_rejected(client, admin_headers, db):
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "http-thing", "kind": "http", "base_url": "http://x", "auth_type": "none"})
    role = client.post("/api/roles", headers=admin_headers, json={"name": "r"}).json()
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "B", "role_id": role["id"]}).json()
    a = _agent_orm(db, agent["api_key_prefix"])
    with pytest.raises(ValueError, match="not a broker connector"):
        publish_message(db, a, connector_name="http-thing", topic="t", message="x",
                        producer=FakeProducer())


def test_publish_endpoint_end_to_end(client, admin_headers, monkeypatch, db):
    # Route through the HTTP endpoint with an injected producer via monkeypatch.
    from agentops import brokers
    fake = FakeProducer()
    monkeypatch.setattr(brokers, "_build_producer", lambda connector: fake)
    agent = _broker_agent(client, admin_headers, actions=["broker.publish"])
    r = client.post("/api/v1/gateway/publish", headers={"X-API-Key": agent["api_key"]},
                    json={"connector": "events", "topic": "orders.created",
                          "message": {"order": 42}})
    assert r.status_code == 200, r.text
    assert r.json()["executed"] is True
    assert fake.sent[0][0] == "orders.created"
