# =============================================
# Generated Code - Prompt 3 (naive)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

import psycopg2
import psycopg2.extras

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config — pull every sensitive value from the environment, never hardcode
# ---------------------------------------------------------------------------

DB_CONFIG: dict[str, str | int] = {
    "host":     os.environ["DB_HOST"],
    "port":     int(os.environ.get("DB_PORT", 5432)),
    "dbname":   os.environ["DB_NAME"],
    "user":     os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"],
    "sslmode":  os.environ.get("DB_SSLMODE", "require"),
    "connect_timeout": 10,
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Order:
    order_id:    int
    customer_id: int
    status:      str
    total:       Decimal
    created_at:  datetime
    updated_at:  datetime


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

@contextmanager
def get_connection():
    """
    Yield a psycopg2 connection and guarantee cleanup.
    The caller should not commit/rollback — this context manager is
    read-only; adapt it if you need write transactions.
    """
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        yield conn
    except psycopg2.OperationalError as exc:
        logger.error("Could not connect to the database: %s", exc)
        raise
    finally:
        if conn and not conn.closed:
            conn.close()


# ---------------------------------------------------------------------------
# Core query
# ---------------------------------------------------------------------------

_GET_ORDERS_SQL = """
    SELECT
        order_id,
        customer_id,
        status,
        total,
        created_at,
        updated_at
    FROM orders
    WHERE customer_id = %(customer_id)s
    ORDER BY created_at DESC;
"""


def get_orders_by_customer(customer_id: int) -> list[Order]:
    """
    Return every order placed by *customer_id*, newest first.

    Parameters
    ----------
    customer_id : int
        Primary key of the customer in the ``customers`` table.

    Returns
    -------
    list[Order]
        Empty list if the customer exists but has no orders.

    Raises
    ------
    TypeError
        If *customer_id* is not an int (guards against accidental
        SQL-injection vectors before the query even runs).
    psycopg2.DatabaseError
        Re-raised after logging if the query fails.
    """
    if not isinstance(customer_id, int) or isinstance(customer_id, bool):
        raise TypeError(f"customer_id must be an int, got {type(customer_id).__name__}")
    if customer_id <= 0:
        raise ValueError(f"customer_id must be a positive integer, got {customer_id}")

    try:
        with get_connection() as conn:
            # RealDictCursor returns rows as dicts — no positional index guessing
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(_GET_ORDERS_SQL, {"customer_id": customer_id})
                rows = cur.fetchall()

        orders = [Order(**row) for row in rows]
        logger.info(
            "Retrieved %d order(s) for customer_id=%d", len(orders), customer_id
        )
        return orders

    except psycopg2.DatabaseError as exc:
        logger.error(
            "Database error fetching orders for customer_id=%d: %s",
            customer_id, exc,
        )
        raise


# ---------------------------------------------------------------------------
# CLI smoke-test  (python app.py <customer_id>)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        print("Usage: python solution.py <customer_id>")
        sys.exit(1)

    cid = int(sys.argv[1])
    try:
        results = get_orders_by_customer(cid)
    except (TypeError, ValueError) as e:
        print(f"Bad input: {e}")
        sys.exit(1)

    if not results:
        print(f"No orders found for customer {cid}.")
    else:
        print(f"\n{'─' * 72}")
        print(f"  Orders for customer {cid}")
        print(f"{'─' * 72}")
        for o in results:
            print(
                f"  #{o.order_id:<6} | {o.status:<12} | "
                f"${o.total:>10.2f} | {o.created_at:%Y-%m-%d %H:%M}"
            )
        print(f"{'─' * 72}\n")