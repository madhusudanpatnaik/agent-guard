"""Tests for the governed read-only database connector."""

import sqlite3

import pytest


@pytest.fixture
def warehouse_dsn(tmp_path):
    dbfile = tmp_path / "warehouse.db"
    conn = sqlite3.connect(dbfile)
    conn.execute(
        "CREATE TABLE customers (id INTEGER, name TEXT, email TEXT, ssn TEXT, "
        "tier TEXT, balance REAL)"
    )
    conn.executemany(
        "INSERT INTO customers VALUES (?,?,?,?,?,?)",
        [
            (1, "Dana Reyes", "dana@example.com", "452-11-9832", "vip", 1200.50),
            (2, "Sam Okafor", "sam@example.com", "610-22-7788", "standard", 43.0),
        ],
    )
    conn.commit()
    conn.close()
    return f"sqlite:///{dbfile}"


@pytest.fixture
def warehouse(client, admin_headers, warehouse_dsn):
    # The DSN (with any credentials) is vaulted; base_url is only a label.
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "warehouse", "kind": "database", "base_url": "analytics-warehouse",
        "auth_type": "none", "auth_secret": warehouse_dsn})

    role = client.post("/api/roles", headers=admin_headers, json={"name": "analyst"}).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "name": "read-warehouse", "effect": "allow", "resource": "db:warehouse",
        "actions": ["db.select"]})

    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "AnalystBot", "role_id": rid}).json()
    return {"key": {"X-API-Key": agent["api_key"]}, "admin": admin_headers}


def _query(client, key, sql, **kw):
    return client.post("/api/v1/gateway/query", headers=key,
                       json={"connector": "warehouse", "sql": sql, **kw})


def test_dsn_is_never_returned(client, admin_headers, warehouse):
    conns = client.get("/api/connectors", headers=admin_headers).json()
    wh = next(c for c in conns if c["name"] == "warehouse")
    assert "auth_secret" not in wh and "auth_secret_encrypted" not in wh
    assert wh["has_secret"] is True
    assert "sqlite" not in wh["base_url"]  # DSN not leaked via base_url


def test_select_executes_with_pii_redacted(client, warehouse):
    r = _query(client, warehouse["key"],
               "SELECT * FROM customers WHERE tier = :tier", params={"tier": "vip"}).json()
    assert r["executed"] is True
    assert r["row_count"] == 1
    row = r["rows"][0]
    assert row["name"] == "Dana Reyes"
    assert row["ssn"] != "452-11-9832"          # SSN redacted
    assert row["email"] != "dana@example.com"   # email redacted
    detectors = {f["detector"] for f in r["response_dlp_findings"]}
    assert "us_ssn" in detectors


def test_bound_params_are_used(client, warehouse):
    r = _query(client, warehouse["key"],
               "SELECT COUNT(*) AS n FROM customers WHERE balance > :min",
               params={"min": 100}).json()
    assert r["executed"] is True
    assert r["rows"][0]["n"] == 1


def test_write_is_refused_read_only(client, warehouse):
    r = _query(client, warehouse["key"],
               "UPDATE customers SET tier = 'vip' WHERE id = 2").json()
    assert r["executed"] is False
    assert r["decision"] == "deny"
    assert "read-only" in r["error"]


def test_multiple_statements_refused(client, warehouse):
    r = _query(client, warehouse["key"],
               "SELECT * FROM customers; DROP TABLE customers").json()
    assert r["executed"] is False
    assert "multiple statements" in r["error"]


def test_policy_denies_unpermitted_connector(client, admin_headers, warehouse_dsn):
    # A role with no db policy must be denied by default-deny.
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "warehouse", "kind": "database", "base_url": "wh",
        "auth_type": "none", "auth_secret": warehouse_dsn})
    role = client.post("/api/roles", headers=admin_headers, json={"name": "noaccess"}).json()
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "NoBot", "role_id": role["id"]}).json()
    r = _query(client, {"X-API-Key": agent["api_key"]}, "SELECT * FROM customers").json()
    assert r["executed"] is False
    assert r["decision"] == "deny"


def test_read_path_enforces_db_level_read_only(warehouse_dsn):
    # Defense in depth: even a write that somehow reached _run_query is blocked by
    # the read-only transaction (this is what stops Postgres SELECT..INTO / CTE writes).
    import sqlalchemy.exc

    from agentguard.db_connector import _run_query
    cols, rows = _run_query(warehouse_dsn, "SELECT COUNT(*) AS n FROM customers", {})
    assert rows[0]["n"] == 2
    with pytest.raises(sqlalchemy.exc.SQLAlchemyError):
        _run_query(warehouse_dsn, "INSERT INTO customers (id) VALUES (999)", {})
    # nothing persisted
    cols, rows = _run_query(warehouse_dsn, "SELECT COUNT(*) AS n FROM customers", {})
    assert rows[0]["n"] == 2


def test_non_database_connector_rejected(client, admin_headers):
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "http-thing", "kind": "http", "base_url": "http://x", "auth_type": "none"})
    role = client.post("/api/roles", headers=admin_headers, json={"name": "r2"}).json()
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "B2", "role_id": role["id"]}).json()
    resp = client.post("/api/v1/gateway/query", headers={"X-API-Key": agent["api_key"]},
                       json={"connector": "http-thing", "sql": "SELECT 1"})
    assert resp.status_code == 400
    assert "not a database connector" in resp.json()["detail"]


# --- Governed writes --------------------------------------------------------

@pytest.fixture
def writable_wh(client, admin_headers, tmp_path):
    dbfile = tmp_path / "rw.db"
    conn = sqlite3.connect(dbfile)
    conn.execute("CREATE TABLE tickets (id INTEGER, status TEXT)")
    conn.executemany("INSERT INTO tickets VALUES (?,?)",
                     [(1, "open"), (2, "open"), (3, "open")])
    conn.commit()
    conn.close()
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "wh_rw", "kind": "database", "base_url": "rw", "auth_type": "none",
        "auth_secret": f"sqlite:///{dbfile}", "writable": True, "max_write_rows": 2})
    role = client.post("/api/roles", headers=admin_headers, json={"name": "editor"}).json()
    rid = role["id"]
    for act in ("db.update", "db.delete", "db.insert"):
        client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
            "effect": "allow", "resource": "db:wh_rw", "actions": [act]})
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "EditorBot", "role_id": rid}).json()
    return {"key": {"X-API-Key": agent["api_key"]}, "dbfile": str(dbfile)}


def _count(dbfile, status):
    c = sqlite3.connect(dbfile)
    n = c.execute("SELECT COUNT(*) FROM tickets WHERE status = ?", (status,)).fetchone()[0]
    c.close()
    return n


def _write(client, key, sql, **kw):
    return client.post("/api/v1/gateway/write", headers=key,
                       json={"connector": "wh_rw", "sql": sql, **kw})


def test_write_within_cap_commits(client, writable_wh):
    r = _write(client, writable_wh["key"],
               "UPDATE tickets SET status = :s WHERE id = :id",
               params={"s": "closed", "id": 1}).json()
    assert r["executed"] is True
    assert r["rows_affected"] == 1
    assert _count(writable_wh["dbfile"], "closed") == 1  # actually persisted


def test_write_exceeding_cap_rolls_back(client, writable_wh):
    # No WHERE -> affects all 3 rows > cap of 2 -> must roll back, nothing persisted.
    r = _write(client, writable_wh["key"],
               "UPDATE tickets SET status = 'closed'").json()
    assert r["executed"] is False
    assert "rolled back" in r["error"]
    assert _count(writable_wh["dbfile"], "closed") == 0  # unchanged


def test_ddl_is_rejected(client, writable_wh):
    r = _write(client, writable_wh["key"], "DROP TABLE tickets").json()
    assert r["executed"] is False
    assert "not a permitted write" in r["error"]
    # table still intact
    assert _count(writable_wh["dbfile"], "open") == 3


def test_write_on_readonly_connector_denied(client, admin_headers, tmp_path):
    dbfile = tmp_path / "ro.db"
    conn = sqlite3.connect(dbfile)
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "ro_db", "kind": "database", "base_url": "ro", "auth_type": "none",
        "auth_secret": f"sqlite:///{dbfile}"})  # writable defaults to False
    role = client.post("/api/roles", headers=admin_headers, json={"name": "ed2"}).json()
    client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "db:ro_db", "actions": ["db.insert"]})
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "E2", "role_id": role["id"]}).json()
    r = client.post("/api/v1/gateway/write", headers={"X-API-Key": agent["api_key"]},
                    json={"connector": "ro_db", "sql": "INSERT INTO t VALUES (1)"}).json()
    assert r["executed"] is False
    assert "read-only" in r["error"]


def test_write_policy_denies_without_grant(client, admin_headers, tmp_path):
    dbfile = tmp_path / "w2.db"
    conn = sqlite3.connect(dbfile)
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.commit()
    conn.close()
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "w2", "kind": "database", "base_url": "w2", "auth_type": "none",
        "auth_secret": f"sqlite:///{dbfile}", "writable": True})
    # role with NO write policy
    role = client.post("/api/roles", headers=admin_headers, json={"name": "nowrite"}).json()
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "NW", "role_id": role["id"]}).json()
    r = client.post("/api/v1/gateway/write", headers={"X-API-Key": agent["api_key"]},
                    json={"connector": "w2", "sql": "INSERT INTO t VALUES (1)"}).json()
    assert r["executed"] is False
    assert r["decision"] == "deny"
