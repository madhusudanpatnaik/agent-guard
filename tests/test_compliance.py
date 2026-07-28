"""Tests for compliance evidence reporting."""

import json


def _governed_traffic(client, admin_headers):
    """Produce real evidence: an allow, a deny, and a blocked exfiltration."""
    role = client.post("/api/roles", json={"name": "compliance-demo"},
                       headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "db:customers:*", "actions": ["read"]})
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:**", "actions": ["http.post"]})
    agent = client.post("/api/agents", json={"name": "CBot", "role_id": rid},
                        headers=admin_headers).json()
    key = {"X-API-Key": agent["api_key"]}
    # allowed
    client.post("/api/v1/gateway/authorize", headers=key,
                json={"action_type": "read", "resource": "db:customers:1"})
    # denied (default-deny)
    client.post("/api/v1/gateway/authorize", headers=key,
                json={"action_type": "delete", "resource": "db:secrets:1"})
    # exfiltration blocked by DLP
    client.post("/api/v1/gateway/authorize", headers=key,
                json={"action_type": "http.post", "resource": "http:evil/exfil",
                      "payload": {"k": "AKIAIOSFODNN7EXAMPLE"}})
    return key


def test_lists_supported_frameworks(client, admin_headers):
    fws = client.get("/api/compliance/frameworks", headers=admin_headers).json()
    ids = {f["id"] for f in fws}
    assert {"soc2", "gdpr", "hipaa", "pci_dss"} <= ids
    soc2 = next(f for f in fws if f["id"] == "soc2")
    assert soc2["controls"] and all(c["id"] and c["requirement"] for c in soc2["controls"])


def test_report_contains_real_evidence(client, admin_headers):
    _governed_traffic(client, admin_headers)
    r = client.post("/api/compliance/report", headers=admin_headers,
                    json={"framework": "soc2"})
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["framework"] == "soc2"
    by_id = {c["id"]: c for c in rep["controls"]}
    # Access control saw governed decisions.
    assert by_id["CC6.1"]["status"] == "satisfied"
    assert by_id["CC6.1"]["evidence_count"] >= 3
    # Exfiltration prevention has the DLP block as evidence.
    assert by_id["CC6.6"]["status"] == "satisfied"
    assert by_id["CC6.6"]["evidence_count"] >= 1
    # Evidence carries concrete ledger rows, not just counts.
    assert by_id["CC6.1"]["sample"], "expected sample ledger records"


def test_report_embeds_ledger_attestation(client, admin_headers):
    _governed_traffic(client, admin_headers)
    rep = client.post("/api/compliance/report", headers=admin_headers,
                      json={"framework": "soc2"}).json()
    att = rep["ledger_attestation"]
    assert att["chain_valid"] is True
    assert att["records"] >= 3
    assert len(att["head_hash"]) == 64      # real hash, not a placeholder
    assert "hash chain" in att["statement"]


def test_report_is_honest_about_gaps(client, admin_headers):
    """A control with no evidence must be reported as a gap, not silently passed."""
    # Fresh org with NO traffic at all.
    rep = client.post("/api/compliance/report", headers=admin_headers,
                      json={"framework": "soc2"}).json()
    statuses = {c["id"]: c["status"] for c in rep["controls"]}
    # Nothing happened, so evidence-backed controls must NOT claim satisfied.
    assert statuses["CC6.6"] == "not_exercised"
    assert "CC6.6" in rep["gaps"]
    assert rep["coverage"]["coverage_pct"] < 100
    # …but structural controls (credential isolation) hold by design.
    assert statuses["CC6.7"] == "satisfied"


def test_unknown_framework_rejected(client, admin_headers):
    r = client.post("/api/compliance/report", headers=admin_headers,
                    json={"framework": "iso-9001"})
    assert r.status_code == 400
    assert "unknown framework" in r.json()["detail"]


def test_invalid_window_rejected(client, admin_headers):
    r = client.post("/api/compliance/report", headers=admin_headers, json={
        "framework": "soc2", "since": "2026-06-01T00:00:00Z",
        "until": "2026-01-01T00:00:00Z"})
    assert r.status_code == 400


def test_markdown_render(client, admin_headers):
    _governed_traffic(client, admin_headers)
    r = client.post("/api/compliance/report.md", headers=admin_headers,
                    json={"framework": "gdpr"})
    assert r.status_code == 200
    body = r.text
    assert body.startswith("# Compliance Evidence Report")
    assert "Ledger integrity attestation" in body
    assert "Art.30" in body                       # a GDPR control is documented
    assert "attachment" in r.headers.get("content-disposition", "")


def test_summary_endpoint(client, admin_headers):
    _governed_traffic(client, admin_headers)
    s = client.get("/api/compliance/summary?framework=hipaa", headers=admin_headers).json()
    assert s["framework"] == "hipaa"
    assert s["chain_valid"] is True
    assert 0 <= s["coverage"]["coverage_pct"] <= 100


def test_report_is_org_scoped(client, admin_headers):
    """One tenant's evidence must never appear in another tenant's report."""
    _governed_traffic(client, admin_headers)          # org A traffic
    org = client.post("/api/orgs", json={"name": "CompB", "slug": "compb"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "c@c.example", "password": "cpass12345", "role": "admin"},
                headers=admin_headers)
    tok = client.post("/api/auth/login",
                      json={"email": "c@c.example", "password": "cpass12345"}).json()
    bh = {"Authorization": f"Bearer {tok['access_token']}"}

    rep_b = client.post("/api/compliance/report", headers=bh,
                        json={"framework": "soc2"}).json()
    by_id = {c["id"]: c for c in rep_b["controls"]}
    assert by_id["CC6.1"]["evidence_count"] == 0     # org A's decisions excluded
    assert by_id["CC6.6"]["evidence_count"] == 0
    assert "evil/exfil" not in json.dumps(rep_b)     # no leaked resource strings


def test_report_requires_auth(client):
    assert client.post("/api/compliance/report",
                       json={"framework": "soc2"}).status_code == 401
