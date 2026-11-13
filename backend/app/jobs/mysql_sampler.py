from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import date, datetime, time as dt_time
from decimal import Decimal
import inspect
import re
import time
from typing import Any

import pymysql
from pymysql.cursors import DictCursor, SSDictCursor

from app.common.errors import BadRequestError
from app.engine.field_router import validate_field_role

SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
DB_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$")

_FORBIDDEN_WHERE_KEYWORDS: frozenset[str] = frozenset(
    {
        "SELECT",
        "UNION",
        "INSERT",
        "UPDATE",
        "DELETE",
        "REPLACE",
        "MERGE",
        "DROP",
        "ALTER",
        "TRUNCATE",
        "CREATE",
        "RENAME",
        "GRANT",
        "REVOKE",
        "SET",
        "USE",
        "SHOW",
        "DESCRIBE",
        "EXPLAIN",
        "CALL",
        "EXEC",
        "EXECUTE",
        "PREPARE",
        "DEALLOCATE",
        "HANDLER",
        "LOAD",
        "INTO",
        "OUTFILE",
        "DUMPFILE",
        "LOCK",
        "UNLOCK",
        "COMMIT",
        "ROLLBACK",
        "START",
        "BEGIN",
        "XA",
        "SHUTDOWN",
        "KILL",
        "SLEEP",
        "BENCHMARK",
        "GET_LOCK",
        "RELEASE_LOCK",
        "IS_FREE_LOCK",
        "IS_USED_LOCK",
        "LOAD_FILE",
        "INFORMATION_SCHEMA",
        "PERFORMANCE_SCHEMA",
        "MYSQL",
        "SYS",
        "FROM",
        "JOIN",
        "HAVING",
        "GROUP",
        "ORDER",
        "LIMIT",
        "OFFSET",
        "FOR",
        "PROCEDURE",
        "FUNCTION",
        "TRIGGER",
        "EVENT",
        "VIEW",
        "DATABASE",
        "SCHEMA",
        "TABLE",
    }
)

MysqlConnectorFactory = Callable[..., Any]


def validate_sql_identifier(name: Any, kind: str = "identifier") -> str:
    if not isinstance(name, str) or not SQL_IDENTIFIER_RE.match(name.strip()):
        raise BadRequestError(f"Invalid SQL {kind} identifier")
    return name.strip()


def validate_db_name(name: Any) -> str:
    if not isinstance(name, str) or not DB_NAME_RE.match(name.strip()):
        raise BadRequestError("Invalid database name")
    return name.strip()


def validate_allowed_tables(raw_tables: Sequence[Any] | None) -> list[str]:
    if (
        raw_tables is None
        or isinstance(raw_tables, (str, bytes))
        or not isinstance(raw_tables, Sequence)
    ):
        raise BadRequestError("allowed_tables must be a non-empty list of table names")
    cleaned: list[str] = []
    seen: set[str] = set()
    for tbl in raw_tables:
        valid = validate_sql_identifier(tbl, kind="table")
        if valid not in seen:
            seen.add(valid)
            cleaned.append(valid)
    if not cleaned:
        raise BadRequestError("allowed_tables must contain at least one table name")
    return cleaned


def validate_column_role_mapping(
    mapping: Mapping[str, Any] | None,
    *,
    allowed_columns: Sequence[str] | None = None,
) -> dict[str, str]:
    if mapping is None:
        return {}
    if not isinstance(mapping, Mapping):
        raise BadRequestError("column_role_mapping must be an object")
    allowed_set = set(allowed_columns) if allowed_columns is not None else None
    cleaned: dict[str, str] = {}
    for col, raw_role in mapping.items():
        if not isinstance(col, str) or not col.strip():
            raise BadRequestError("Invalid column name in column_role_mapping")
        key = col.strip()
        if not key.startswith("$"):
            validate_sql_identifier(key, kind="column")
            if allowed_set is not None and key not in allowed_set:
                raise BadRequestError(
                    "column_role_mapping references a column outside select_columns"
                )
        cleaned[key] = validate_field_role(raw_role)
    return cleaned


def validate_where_clause(where_clause: str | None) -> str:
    """Strictly validate single-SELECT WHERE predicate; never echo input in error messages."""
    if where_clause is None:
        return ""
    if not isinstance(where_clause, str):
        raise BadRequestError("Invalid where_clause type")

    clause = where_clause.strip()
    if not clause:
        return ""
    if len(clause) > 2000:
        raise BadRequestError("where_clause exceeds maximum length of 2000 characters")
    if "\x00" in clause or ";" in clause or "--" in clause or "/*" in clause or "*/" in clause:
        raise BadRequestError("Disallowed SQL statement separator or comment in where_clause")

    n = len(clause)
    idx = 0
    paren_depth = 0

    while idx < n:
        ch = clause[idx]

        if ch.isspace():
            idx += 1
            continue

        if ch == "'":
            idx += 1
            closed = False
            while idx < n:
                c = clause[idx]
                if c == "\\":
                    raise BadRequestError(
                        "Backslash escapes are disallowed in where_clause; use standard SQL '' escaping"
                    )
                if c == "'":
                    if idx + 1 < n and clause[idx + 1] == "'":
                        idx += 2
                        continue
                    idx += 1
                    closed = True
                    break
                idx += 1
            if not closed:
                raise BadRequestError("Unclosed string literal in where_clause")
            continue

        if ch == "`":
            end_bt = clause.find("`", idx + 1)
            if end_bt < 0:
                raise BadRequestError("Unclosed backtick identifier in where_clause")
            ident = clause[idx + 1 : end_bt]
            if not SQL_IDENTIFIER_RE.match(ident):
                raise BadRequestError("Invalid backtick identifier in where_clause")
            idx = end_bt + 1
            continue

        if ch in ('"', "#"):
            raise BadRequestError("Disallowed quote or comment character in where_clause")

        if ch == "(":
            paren_depth += 1
            idx += 1
            continue

        if ch == ")":
            paren_depth -= 1
            if paren_depth < 0:
                raise BadRequestError("Unbalanced parentheses in where_clause")
            idx += 1
            continue

        if ch.isalpha() or ch == "_":
            start = idx
            idx += 1
            while idx < n and (clause[idx].isalnum() or clause[idx] == "_"):
                idx += 1
            token = clause[start:idx].upper()
            if token in _FORBIDDEN_WHERE_KEYWORDS:
                raise BadRequestError(f"Disallowed SQL keyword '{token}' in where_clause")
            continue

        if ch.isdigit():
            idx += 1
            has_dot = False
            while idx < n and (clause[idx].isdigit() or (clause[idx] == "." and not has_dot)):
                if clause[idx] == ".":
                    has_dot = True
                idx += 1
            if idx < n and (clause[idx].isalpha() or clause[idx] == "_"):
                raise BadRequestError("Invalid numeric token in where_clause")
            continue

        if clause.startswith(("!=", "<>", "<=", ">="), idx):
            idx += 2
            continue

        if ch in ("=", "<", ">", ",", "+", "-", "*", "/", "."):
            idx += 1
            continue

        raise BadRequestError("Disallowed character in where_clause")

    if paren_depth != 0:
        raise BadRequestError("Unbalanced parentheses in where_clause")

    return clause


def redact_where_clause_literals(where_clause: str | None) -> str:
    """Replace string and long numeric literals with '?' for zero-plaintext audit metadata."""
    clean = validate_where_clause(where_clause)
    if not clean:
        return ""
    out: list[str] = []
    i = 0
    n = len(clean)
    while i < n:
        if clean[i] == "'":
            i += 1
            while i < n:
                if clean[i] == "'":
                    if i + 1 < n and clean[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append("'?'")
        else:
            out.append(clean[i])
            i += 1
    redacted = "".join(out)
    return re.sub(r"\b\d{4,}\b", "?", redacted)


def build_readonly_sample_query(
    *,
    table_name: str,
    select_columns: Sequence[str],
    allowed_tables: Sequence[str],
    where_clause: str | None = None,
    limit_rows: int = 1000,
) -> tuple[str, tuple[int]]:
    clean_table = validate_sql_identifier(table_name, kind="table")
    valid_allowlist = validate_allowed_tables(allowed_tables)
    if clean_table not in valid_allowlist:
        raise BadRequestError("Target table is not in datasource allowed_tables whitelist")

    if (
        isinstance(select_columns, (str, bytes))
        or not isinstance(select_columns, Sequence)
        or not select_columns
        or len(select_columns) > 128
    ):
        raise BadRequestError("select_columns must contain between 1 and 128 column names")

    clean_cols: list[str] = []
    seen_cols: set[str] = set()
    for col in select_columns:
        valid_col = validate_sql_identifier(col, kind="column")
        if valid_col not in seen_cols:
            seen_cols.add(valid_col)
            clean_cols.append(valid_col)

    if isinstance(limit_rows, bool) or not isinstance(limit_rows, int) or limit_rows < 1 or limit_rows > 100000:
        raise BadRequestError("limit_rows must be between 1 and 100000")

    clean_where = validate_where_clause(where_clause)
    quoted_cols = ", ".join(f"`{col}`" for col in clean_cols)
    sql = f"SELECT {quoted_cols} FROM `{clean_table}`"
    if clean_where:
        sql = f"{sql} WHERE {clean_where}"
    sql = f"{sql} LIMIT %s"
    return sql, (limit_rows,)


def default_pymysql_connector_factory(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    streaming: bool = False,
) -> Any:
    cursor_cls = SSDictCursor if streaming else DictCursor
    return pymysql.connect(
        host=host,
        port=int(port),
        user=user,
        password=password,
        database=database,
        charset="utf8mb4",
        connect_timeout=5,
        read_timeout=30,
        write_timeout=10,
        autocommit=False,
        cursorclass=cursor_cls,
    )


def _open_mysql_conn(
    factory: MysqlConnectorFactory,
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    streaming: bool,
) -> Any:
    sig = inspect.signature(factory)
    accepts_var_kw = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    kwargs: dict[str, Any] = {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "database": database,
    }
    if accepts_var_kw or "streaming" in sig.parameters:
        kwargs["streaming"] = streaming
    return factory(**kwargs)


def verify_readonly_mysql_connection(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    connector_factory: MysqlConnectorFactory | None = None,
) -> int:
    """Connect and verify SET SESSION TRANSACTION READ ONLY + SELECT 1; returns latency_ms."""
    factory = connector_factory or default_pymysql_connector_factory
    t0 = time.perf_counter()
    conn = _open_mysql_conn(
        factory,
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        streaming=False,
    )
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SET SESSION TRANSACTION READ ONLY")
        cur.execute("SELECT 1")
        row = cur.fetchone()
        if row is None:
            raise RuntimeError("Read-only probe returned empty result")
        return max(0, int(round((time.perf_counter() - t0) * 1000)))
    finally:
        if cur is not None:
            try:
                cur.close()
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass


def _normalize_sql_value(val: Any) -> Any:
    if val is None or isinstance(val, (str, int, float, bool)):
        return val
    if isinstance(val, (datetime, date, dt_time)):
        return val.isoformat()
    if isinstance(val, Decimal):
        return str(val)
    if isinstance(val, (bytes, bytearray)):
        return bytes(val).decode("utf-8", errors="replace")
    return str(val)


def stream_readonly_mysql_rows(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    sql: str,
    params: tuple[Any, ...],
    select_columns: Sequence[str],
    connector_factory: MysqlConnectorFactory | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream rows under SET SESSION TRANSACTION READ ONLY via server-side cursor."""
    if not sql.startswith("SELECT ") or ";" in sql:
        raise BadRequestError("Only single read-only SELECT queries are permitted")

    factory = connector_factory or default_pymysql_connector_factory
    conn = _open_mysql_conn(
        factory,
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        streaming=True,
    )
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SET SESSION TRANSACTION READ ONLY")
        cur.execute(sql, params)
        while True:
            raw_row = cur.fetchone()
            if raw_row is None:
                break
            if isinstance(raw_row, Mapping):
                yield {str(k): _normalize_sql_value(v) for k, v in raw_row.items()}
            elif isinstance(raw_row, (tuple, list)):
                yield {
                    col: _normalize_sql_value(raw_row[i] if i < len(raw_row) else None)
                    for i, col in enumerate(select_columns)
                }
            else:
                raise RuntimeError("Unexpected cursor row type")
    finally:
        if cur is not None:
            try:
                cur.close()
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass
