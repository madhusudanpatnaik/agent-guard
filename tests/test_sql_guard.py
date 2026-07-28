"""Tests for AST-based SQL governance.

Several of these are regressions for **verified bypasses of the previous
regex/string classifier** — they fail against text matching and pass only with
a real parse tree.
"""

import pytest

from agentops.sql_guard import analyze, check_column_access


def _ok(sql, dialect="postgres"):
    return analyze(sql, dialect=dialect, read_only=True).ok


# --- legitimate reads must still work ---------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT id, name FROM customers",
    "(SELECT * FROM customers)",                       # parenthesized read
    "WITH t AS (SELECT 1 AS x) SELECT * FROM t",       # read CTE
    "SELECT a FROM t UNION SELECT b FROM u",
    "SELECT count(*) FROM orders WHERE total > :min",
    "-- a comment\nSELECT 1",
])
def test_legitimate_reads_allowed(sql):
    assert _ok(sql) is True


# --- previously-bypassable attacks (regressions) ----------------------------

def test_data_modifying_cte_is_blocked():
    """BYPASS of the old classifier: verb is WITH, but it DELETEs."""
    a = analyze("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
                dialect="postgres", read_only=True)
    assert a.ok is False
    assert "DELETE" in a.error


def test_comment_split_function_name_is_blocked():
    """BYPASS of the old classifier: `db/**/link_connect` evaded the regex."""
    assert _ok("SELECT db/**/link_connect('host=evil')") is False


@pytest.mark.parametrize("sql", [
    "SELECT pg_sleep(100)",
    "SELECT pg_sleep\n(100)",                  # newline inside the call
    "SELECT PG_SLEEP(100)",                    # casing
    "SELECT * FROM (SELECT pg_sleep(99)) t",   # nested in a subquery
    "SELECT dblink_connect('host=evil.com')",
    "SELECT pg_read_file('/etc/passwd')",
])
def test_dangerous_functions_blocked_anywhere_in_tree(sql):
    assert _ok(sql) is False


@pytest.mark.parametrize("sql", [
    "DROP TABLE customers",
    "/*x*/ DROP TABLE customers",
    "UPDATE customers SET tier = 'vip'",
    "INSERT INTO t VALUES (1)",
    "SELECT 1; DROP TABLE t",                  # stacked statements
])
def test_non_reads_refused_on_read_path(sql):
    assert _ok(sql) is False


def test_unparseable_sql_fails_closed():
    a = analyze("SELECT FROM WHERE ((", dialect="postgres")
    assert a.ok is False and a.error


# --- write path --------------------------------------------------------------

@pytest.mark.parametrize("sql,allowed", [
    ("UPDATE tickets SET status = 'closed' WHERE id = 1", True),
    ("INSERT INTO tickets (id) VALUES (1)", True),
    ("DELETE FROM tickets WHERE id = 1", True),
    ("DROP TABLE tickets", False),          # DDL never
    ("TRUNCATE TABLE tickets", False),
    ("SELECT * FROM tickets", False),       # a read is not a write
    ("UPDATE t SET x = pg_sleep(10)", False),  # dangerous fn on write path too
])
def test_write_path_classification(sql, allowed):
    assert analyze(sql, dialect="postgres", read_only=False).ok is allowed


# --- AST-only capabilities ---------------------------------------------------

def test_extracts_tables_and_columns():
    """Structural extraction that text matching cannot do."""
    a = analyze("SELECT c.name, c.ssn FROM customers c JOIN orders o ON o.cid = c.id",
                dialect="postgres")
    assert a.ok is True
    assert {"customers", "orders"} <= a.tables
    assert {"name", "ssn"} <= a.columns


def test_column_level_authorization():
    """Deny a query that touches a restricted column — needs the AST."""
    a = analyze("SELECT name, ssn FROM customers", dialect="postgres")
    assert check_column_access(a, {"ssn"}) is not None
    assert check_column_access(a, {"salary"}) is None


def test_dialect_specific_parsing():
    """MySQL-only syntax parses under the mysql dialect."""
    assert analyze("SELECT `name` FROM `customers`", dialect="mysql").ok is True
