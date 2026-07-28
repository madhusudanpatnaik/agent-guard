"""Tests for policy intelligence (shadow/redundant/broad/unused + hotspots)."""


def _role(client, admin_headers, name):
    return client.post("/api/roles", json={"name": name}, headers=admin_headers).json()["id"]


def _pol(client, admin_headers, rid, **kw):
    return client.post(f"/api/roles/{rid}/policies", json=kw, headers=admin_headers).json()


def _analyze(client, admin_headers, rid):
    return client.get(f"/api/roles/{rid}/analysis", headers=admin_headers).json()


def test_detects_shadowed_allow(client, admin_headers):
    rid = _role(client, admin_headers, "shadowed")
    _pol(client, admin_headers, rid, name="allow-read", effect="allow",
         resource="db:customers:*", actions=["read"], priority=1)
    _pol(client, admin_headers, rid, name="deny-all-cust", effect="deny",
         resource="db:customers:*", actions=["*"], priority=100)
    a = _analyze(client, admin_headers, rid)
    kinds = {f["kind"] for f in a["findings"]}
    assert "shadowed_allow" in kinds


def test_detects_redundant_policy(client, admin_headers):
    rid = _role(client, admin_headers, "dup")
    _pol(client, admin_headers, rid, effect="allow", resource="db:x", actions=["read"])
    _pol(client, admin_headers, rid, effect="allow", resource="db:x", actions=["read"])
    a = _analyze(client, admin_headers, rid)
    assert any(f["kind"] == "redundant" for f in a["findings"])


def test_detects_overly_broad_allow(client, admin_headers):
    rid = _role(client, admin_headers, "broad")
    _pol(client, admin_headers, rid, effect="allow", resource="**", actions=["*"])
    a = _analyze(client, admin_headers, rid)
    broad = [f for f in a["findings"] if f["kind"] == "overly_broad"]
    assert broad and broad[0]["severity"] == "warning"


def test_clean_role_has_no_warnings(client, admin_headers):
    rid = _role(client, admin_headers, "clean")
    _pol(client, admin_headers, rid, name="r", effect="allow",
         resource="db:orders:*", actions=["read"])
    _pol(client, admin_headers, rid, name="w", effect="allow",
         resource="db:invoices:*", actions=["write"])
    a = _analyze(client, admin_headers, rid)
    assert not any(f["severity"] == "warning" for f in a["findings"])


def test_unused_policy_detected_after_traffic(client, admin_headers):
    rid = _role(client, admin_headers, "used")
    used = _pol(client, admin_headers, rid, name="used", effect="allow",
               resource="db:a", actions=["read"])
    unused = _pol(client, admin_headers, rid, name="never", effect="allow",
                 resource="db:z", actions=["read"])
    agent = client.post("/api/agents", json={"name": "UBot", "role_id": rid},
                        headers=admin_headers).json()
    # Exercise only the 'used' policy.
    client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                json={"action_type": "read", "resource": "db:a"})
    a = _analyze(client, admin_headers, rid)
    assert unused["id"] in a["unused_policy_ids"]
    assert used["id"] not in a["unused_policy_ids"]


def test_denial_hotspots_surface_repeated_denials(client, admin_headers):
    rid = _role(client, admin_headers, "hot")
    # No policy for db:secret -> default-deny; hit it repeatedly.
    _pol(client, admin_headers, rid, effect="allow", resource="db:ok", actions=["read"])
    agent = client.post("/api/agents", json={"name": "HBot", "role_id": rid},
                        headers=admin_headers).json()
    for _ in range(3):
        client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "read", "resource": "db:secret"})
    a = _analyze(client, admin_headers, rid)
    hotspots = a["denial_hotspots"]
    assert any(h["resource"] == "db:secret" and h["denials"] >= 3 for h in hotspots)


def test_analysis_is_tenant_scoped(client, admin_headers):
    rid = _role(client, admin_headers, "mine")
    org = client.post("/api/orgs", json={"name": "Zeta", "slug": "zeta"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "z@z.example", "password": "zpass12345", "role": "admin"},
                headers=admin_headers)
    z = client.post("/api/auth/login",
                    json={"email": "z@z.example", "password": "zpass12345"}).json()
    zh = {"Authorization": f"Bearer {z['access_token']}"}
    assert client.get(f"/api/roles/{rid}/analysis", headers=zh).status_code == 404
