"""Tests for policy recommendations generated from default-deny gaps."""


def _role(client, admin_headers, name):
    return client.post("/api/roles", json={"name": name}, headers=admin_headers).json()["id"]


def _agent(client, admin_headers, rid, name="RecBot"):
    return client.post("/api/agents", json={"name": name, "role_id": rid},
                       headers=admin_headers).json()


def _authorize(client, key, action, resource, **body):
    return client.post("/api/v1/gateway/authorize", headers={"X-API-Key": key},
                       json={"action_type": action, "resource": resource, **body})


def _recommend(client, admin_headers, rid):
    return client.get(f"/api/roles/{rid}/recommendations", headers=admin_headers).json()


def test_recommends_generalized_policy_for_repeated_denials(client, admin_headers):
    rid = _role(client, admin_headers, "gap")
    agent = _agent(client, admin_headers, rid)
    key = agent["api_key"]
    # Repeated default-deny on per-id resources -> should collapse to db:customers:*
    for i in range(5):
        _authorize(client, key, "read", f"db:customers:{i}")
    recs = _recommend(client, admin_headers, rid)
    assert recs, "expected a recommendation for the recurring gap"
    top = recs[0]
    assert top["resource"] == "db:customers:*"     # generalized from per-id denials
    assert "read" in top["actions"]
    assert top["denials"] >= 5
    assert top["confidence"] == "high"             # 5 denials across 5 distinct targets


def test_does_not_recommend_for_dlp_or_deny_policy(client, admin_headers):
    rid = _role(client, admin_headers, "intentional")
    # Explicit deny policy — denials here are intentional, not a gap.
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "deny", "resource": "db:secret:*", "actions": ["*"]})
    agent = _agent(client, admin_headers, rid)
    for i in range(3):
        _authorize(client, agent["api_key"], "read", f"db:secret:{i}")
    recs = _recommend(client, admin_headers, rid)
    # The deny-policy block is not a default-deny gap -> no recommendation for it.
    assert not any(r["resource"].startswith("db:secret") for r in recs)


def test_existing_allow_suppresses_recommendation(client, admin_headers):
    rid = _role(client, admin_headers, "covered")
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "db:orders:*", "actions": ["read"]})
    agent = _agent(client, admin_headers, rid)
    # These are allowed, so no denials accrue and nothing is recommended.
    for i in range(3):
        _authorize(client, agent["api_key"], "read", f"db:orders:{i}")
    recs = _recommend(client, admin_headers, rid)
    assert not any(r["resource"] == "db:orders:*" for r in recs)


def test_below_threshold_not_recommended(client, admin_headers):
    rid = _role(client, admin_headers, "rare")
    agent = _agent(client, admin_headers, rid)
    _authorize(client, agent["api_key"], "read", "db:onceonly:1")  # single denial
    recs = _recommend(client, admin_headers, rid)
    assert not any(r["resource"] == "db:onceonly:*" for r in recs)


def test_apply_recommendation_creates_working_policy(client, admin_headers):
    rid = _role(client, admin_headers, "apply")
    agent = _agent(client, admin_headers, rid)
    key = agent["api_key"]
    for i in range(3):
        _authorize(client, key, "read", f"db:widgets:{i}")
    rec = _recommend(client, admin_headers, rid)[0]

    r = client.post(f"/api/roles/{rid}/recommendations/apply", headers=admin_headers,
                    json={"resource": rec["resource"], "actions": rec["actions"]})
    assert r.status_code == 201
    assert r.json()["effect"] == "allow"

    # The previously-denied action is now allowed.
    after = _authorize(client, key, "read", "db:widgets:99").json()
    assert after["decision"] == "allow"


def test_recommendations_are_tenant_scoped(client, admin_headers):
    rid = _role(client, admin_headers, "mine2")
    org = client.post("/api/orgs", json={"name": "Rec", "slug": "rec"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "r@r.example", "password": "rpass12345", "role": "admin"},
                headers=admin_headers)
    tok = client.post("/api/auth/login",
                      json={"email": "r@r.example", "password": "rpass12345"}).json()
    rh = {"Authorization": f"Bearer {tok['access_token']}"}
    assert client.get(f"/api/roles/{rid}/recommendations", headers=rh).status_code == 404
