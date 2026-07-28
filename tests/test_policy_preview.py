"""Tests for the policy impact preview (safe-apply dry-run)."""


def _role(client, admin_headers, name):
    return client.post("/api/roles", json={"name": name}, headers=admin_headers).json()["id"]


def _agent(client, admin_headers, rid, name="PrevBot"):
    return client.post("/api/agents", json={"name": name, "role_id": rid},
                       headers=admin_headers).json()


def _authorize(client, key, action, resource, **body):
    return client.post("/api/v1/gateway/authorize", headers={"X-API-Key": key},
                       json={"action_type": action, "resource": resource, **body})


def _preview(client, admin_headers, rid, resource, actions):
    return client.post(f"/api/roles/{rid}/policies/preview", headers=admin_headers,
                       json={"resource": resource, "actions": actions}).json()


def test_preview_counts_newly_allowed(client, admin_headers):
    rid = _role(client, admin_headers, "prev")
    key = _agent(client, admin_headers, rid)["api_key"]
    for i in range(3):
        _authorize(client, key, "read", f"db:reports:{i}")   # default-denied
    imp = _preview(client, admin_headers, rid, "db:reports:*", ["read"])
    assert imp["would_allow"] == 3
    assert imp["sensitive_allow"] == 0
    assert any(s["resource"].startswith("db:reports:") for s in imp["sample"])


def test_preview_flags_sensitive_dlp_traffic(client, admin_headers):
    rid = _role(client, admin_headers, "prevdlp")
    key = _agent(client, admin_headers, rid)["api_key"]
    # A denied egress action whose payload carried a secret (DLP finding recorded).
    _authorize(client, key, "http.post", "http:partner/hook",
               payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    imp = _preview(client, admin_headers, rid, "http:**", ["http.post"])
    # The DLP-exfil action stays blocked by the egress guard even with the allow,
    # so it must NOT be counted as newly-allowed.
    assert all(s["resource"] != "http:partner/hook" for s in imp["sample"])


def test_preview_warns_on_overly_broad_candidate(client, admin_headers):
    rid = _role(client, admin_headers, "prevbroad")
    key = _agent(client, admin_headers, rid)["api_key"]
    _authorize(client, key, "read", "db:x:1")
    imp = _preview(client, admin_headers, rid, "**", ["*"])
    assert any("least privilege" in w.lower() for w in imp["warnings"])


def test_preview_warns_when_no_traffic_affected(client, admin_headers):
    rid = _role(client, admin_headers, "prevnone")
    imp = _preview(client, admin_headers, rid, "db:unused:*", ["read"])
    assert imp["would_allow"] == 0
    assert any("no recent denied traffic" in w.lower() for w in imp["warnings"])


def test_preview_respects_existing_deny(client, admin_headers):
    rid = _role(client, admin_headers, "prevdeny")
    # Explicit deny that overrides — a candidate allow can't flip these.
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "deny", "resource": "db:locked:*", "actions": ["*"], "priority": 100})
    key = _agent(client, admin_headers, rid)["api_key"]
    for i in range(2):
        _authorize(client, key, "read", f"db:locked:{i}")
    imp = _preview(client, admin_headers, rid, "db:locked:*", ["read"])
    assert imp["would_allow"] == 0  # deny-overrides-allow, so nothing flips


def test_preview_is_tenant_scoped(client, admin_headers):
    rid = _role(client, admin_headers, "prevscope")
    org = client.post("/api/orgs", json={"name": "Prev", "slug": "prev"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "p@p.example", "password": "ppass12345", "role": "admin"},
                headers=admin_headers)
    tok = client.post("/api/auth/login",
                      json={"email": "p@p.example", "password": "ppass12345"}).json()
    ph = {"Authorization": f"Bearer {tok['access_token']}"}
    r = client.post(f"/api/roles/{rid}/policies/preview", headers=ph,
                    json={"resource": "db:x", "actions": ["read"]})
    assert r.status_code == 404


def test_preview_writes_nothing_to_ledger(client, admin_headers):
    rid = _role(client, admin_headers, "prevclean")
    key = _agent(client, admin_headers, rid)["api_key"]
    _authorize(client, key, "read", "db:a:1")
    before = client.get("/api/audit/verify", headers=admin_headers).json()["length"]
    _preview(client, admin_headers, rid, "db:a:*", ["read"])
    after = client.get("/api/audit/verify", headers=admin_headers).json()["length"]
    assert after == before  # pure dry-run
