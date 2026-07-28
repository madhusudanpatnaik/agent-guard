"""Tests for operator-defined custom DLP detectors."""

from agentops.dlp.scanner import scan_payload_custom


# --- scanner-level ----------------------------------------------------------

def test_custom_detector_matches_and_redacts():
    specs = [{"name": "acme_token", "pattern": r"ACME-[0-9A-F]{8}", "severity": "critical"}]
    result = scan_payload_custom({"note": "token ACME-DEADBEEF here"}, specs)
    names = {f.detector for f in result.findings}
    assert "acme_token" in names
    assert result.blocking is True                      # critical => blocks egress
    assert "ACME-DEADBEEF" not in str(result.redacted)  # redacted out


def test_builtins_still_run_alongside_custom():
    specs = [{"name": "acme_token", "pattern": r"ACME-\d+", "severity": "high"}]
    result = scan_payload_custom({"a": "ACME-42", "b": "AKIAIOSFODNN7EXAMPLE"}, specs)
    names = {f.detector for f in result.findings}
    assert "acme_token" in names and "aws_access_key_id" in names


def test_invalid_custom_pattern_is_ignored():
    specs = [{"name": "bad", "pattern": "([", "severity": "high"}]  # unbalanced
    result = scan_payload_custom({"x": "anything (["}, specs)
    assert not any(f.detector == "bad" for f in result.findings)  # never crashes


def test_bad_severity_is_ignored():
    specs = [{"name": "x", "pattern": "foo", "severity": "extreme"}]
    result = scan_payload_custom({"a": "foo"}, specs)
    assert not any(f.detector == "x" for f in result.findings)


# --- API + end-to-end enforcement ------------------------------------------

def _make_detector(client, admin_headers, **kw):
    body = {"name": "acme_token", "pattern": r"ACME-[0-9A-F]{8}", "severity": "critical", **kw}
    return client.post("/api/detectors", json=body, headers=admin_headers)


def test_detector_crud(client, admin_headers):
    r = _make_detector(client, admin_headers)
    assert r.status_code == 201, r.text
    did = r.json()["id"]
    assert client.get("/api/detectors", headers=admin_headers).json()[0]["name"] == "acme_token"
    upd = client.put(f"/api/detectors/{did}", headers=admin_headers,
                     json={"name": "acme_token", "pattern": r"ACME-\d+", "severity": "high"})
    assert upd.status_code == 200 and upd.json()["severity"] == "high"
    assert client.delete(f"/api/detectors/{did}", headers=admin_headers).status_code == 204


def test_detector_rejects_invalid_regex(client, admin_headers):
    r = _make_detector(client, admin_headers, pattern="([")
    assert r.status_code == 400
    assert "invalid regex" in r.json()["detail"]


def test_detector_name_conflict(client, admin_headers):
    _make_detector(client, admin_headers)
    assert _make_detector(client, admin_headers).status_code == 409


def test_detector_test_endpoint(client, admin_headers):
    r = client.post("/api/detectors/test", headers=admin_headers,
                    json={"pattern": r"ACME-\d+", "sample": "id ACME-77 ok"})
    assert r.json() == {"valid": True, "matched": True, "error": None}
    bad = client.post("/api/detectors/test", headers=admin_headers,
                      json={"pattern": "([", "sample": "x"})
    assert bad.json()["valid"] is False


def test_custom_detector_blocks_egress_end_to_end(client, admin_headers):
    _make_detector(client, admin_headers)  # ACME token, critical
    role = client.post("/api/roles", json={"name": "leaky"}, headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:**", "actions": ["http.post"]})
    agent = client.post("/api/agents", json={"name": "AcmeBot", "role_id": rid},
                        headers=admin_headers).json()
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "http.post", "resource": "http:partner/hook",
                          "payload": {"leak": "our token ACME-DEADBEEF"}}).json()
    # The org's custom detector makes this an exfiltration -> blocked on egress.
    assert r["decision"] == "deny"
    assert any(f["detector"] == "acme_token" for f in r["dlp_findings"])


def test_custom_detectors_are_tenant_scoped(client, admin_headers):
    _make_detector(client, admin_headers)  # in the default org only
    org = client.post("/api/orgs", json={"name": "Det", "slug": "det"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "d@d.example", "password": "dpass12345", "role": "admin"},
                headers=admin_headers)
    tok = client.post("/api/auth/login",
                      json={"email": "d@d.example", "password": "dpass12345"}).json()
    dh = {"Authorization": f"Bearer {tok['access_token']}"}
    assert client.get("/api/detectors", headers=dh).json() == []  # not visible cross-tenant
