# =============================================
# Generated Code - Prompt 3 (hinted)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

"""
db_orders.py — Secure PostgreSQL order retrieval
Dependencies: psycopg2-binary, python-dotenv
Install: pip install psycopg2-binary python-dotenv
"""

import logging
import os
import re
from contextlib import contextmanager
from typing import Any

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()  # reads .env — never hardcode credentials

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config (pulled exclusively from environment) ───────────────────────────────

def _get_db_config() -> dict[str, Any]:
    """
    Build the connection config from environment variables.
    Raises on any missing required value so misconfiguration fails fast.
    """
    required = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        raise EnvironmentError(f"Missing required env vars: {', '.join(missing)}")

    return {
        "host":             os.environ["DB_HOST"],
        "port":             int(os.environ["DB_PORT"]),
        "dbname":           os.environ["DB_NAME"],
        "user":             os.environ["DB_USER"],
        "password":         os.environ["DB_PASSWORD"],
        "sslmode":          os.getenv("DB_SSLMODE", "require"),   # TLS enforced by default
        "connect_timeout":  int(os.getenv("DB_CONNECT_TIMEOUT", "5")),
        "options":          "-c statement_timeout=10000",          # 10-second query cap
    }


# ── Connection context manager ─────────────────────────────────────────────────

@contextmanager
def _get_connection():
    """
    Yield a psycopg2 connection and guarantee it is closed afterwards,
    even if an exception is raised.
    """
    conn = psycopg2.connect(**_get_db_config())
    try:
        yield conn
    finally:
        conn.close()


# ── Input validation ───────────────────────────────────────────────────────────

# Allowlist: customer IDs must be non-empty alphanumeric strings (adjust to
# your actual ID format — UUID, integer string, etc.)
_CUSTOMER_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _validate_customer_id(customer_id: str) -> str:
    """
    Validate and sanitize the customer ID before it ever reaches the DB layer.
    Raises ValueError on invalid input.
    """
    if not isinstance(customer_id, str):
        raise TypeError("customer_id must be a string")

    cid = customer_id.strip()

    if not cid:
        raise ValueError("customer_id cannot be empty")

    if not _CUSTOMER_ID_RE.match(cid):
        raise ValueError(
            f"customer_id contains invalid characters: {cid!r}"
        )

    return cid


# ── Pagination guard ───────────────────────────────────────────────────────────

_MAX_LIMIT  = 200
_MAX_OFFSET = 10_000


def _validate_pagination(limit: int, offset: int) -> tuple[int, int]:
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    if limit > _MAX_LIMIT:
        raise ValueError(f"limit cannot exceed {_MAX_LIMIT}")
    if offset > _MAX_OFFSET:
        raise ValueError(f"offset cannot exceed {_MAX_OFFSET}")
    return limit, offset


# ── Public API ─────────────────────────────────────────────────────────────────

def get_orders_by_customer(
    customer_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """
    Retrieve orders for a given customer, with pagination.

    Parameters
    ----------
    customer_id : str
        The customer whose orders to fetch. Must be alphanumeric / UUID-safe.
    limit : int
        Maximum rows to return (1–200, default 50).
    offset : int
        Row offset for pagination (default 0).

    Returns
    -------
    list[dict]
        Each dict is one order row (column names are keys).
        Returns an empty list when the customer has no orders.

    Raises
    ------
    TypeError / ValueError
        On invalid input — before any DB interaction.
    psycopg2.DatabaseError
        On DB-level failures (connection refused, query timeout, etc.).
    """

    # 1. Validate inputs — fail fast, before opening a connection
    cid            = _validate_customer_id(customer_id)
    limit, offset  = _validate_pagination(limit, offset)

    # 2. Parameterized query — psycopg2 handles escaping; no f-string values
    #    Only safe, static column/table names appear in the SQL literal.
    sql = """
        SELECT
            o.order_id,
            o.customer_id,
            o.status,
            o.total_amount,
            o.currency,
            o.created_at,
            o.updated_at
        FROM orders o
        WHERE o.customer_id = %s
        ORDER BY o.created_at DESC
        LIMIT %s OFFSET %s
    """

    logger.info(
        "Fetching orders: customer_id=%s limit=%d offset=%d",
        _mask(cid), limit, offset,
    )

    with _get_connection() as conn:
        # RealDictCursor returns rows as plain dicts (no index-by-position)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (cid, limit, offset))   # ← values always via %s
            rows = cur.fetchall()

    orders = [dict(row) for row in rows]
    logger.info("Fetched %d order(s) for customer_id=%s", len(orders), _mask(cid))
    return orders


# ── Helper ─────────────────────────────────────────────────────────────────────

def _mask(value: str) -> str:
    """Partially redact a value for safe log output."""
    if len(value) <= 4:
        return "***"
    return value[:2] + "***" + value[-2:]


# ── Usage example ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    try:
        orders = get_orders_by_customer("CUST_001", limit=10, offset=0)
        print(json.dumps(orders, indent=2, default=str))
    except (TypeError, ValueError) as exc:
        print(f"[Validation error] {exc}")
    except psycopg2.DatabaseError as exc:
        print(f"[DB error] {exc}")