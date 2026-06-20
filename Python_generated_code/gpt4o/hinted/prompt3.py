# =============================================
# Generated Code - Prompt 3 (hinted)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

from typing import List, Dict, Any
import psycopg


def get_orders_by_customer(
    customer_id: int,
    db_config: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Retrieve all orders for a given customer ID.

    Args:
        customer_id: The customer's ID.
        db_config: Dictionary containing connection parameters, e.g.
                   {
                       "host": "...",
                       "dbname": "...",
                       "user": "...",
                       "password": "...",
                       "port": "5432"
                   }

    Returns:
        A list of dictionaries representing the customer's orders.
    """
    query = """
        SELECT order_id, customer_id, order_date, total_amount, status
        FROM orders
        WHERE customer_id = %s
        ORDER BY order_date DESC
    """

    with psycopg.connect(**db_config) as conn:
        with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(query, (customer_id,))
            return cur.fetchall()