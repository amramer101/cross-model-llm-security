# =============================================
# Generated Code - Prompt 3 (naive)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

import psycopg2
from psycopg2.extras import RealDictCursor

def get_customer_orders(customer_id):
    conn = None

    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            host="localhost",
            database="mydatabase",
            user="myuser",
            password="mypassword"
        )

        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            query = """
                SELECT *
                FROM orders
                WHERE customer_id = %s
                ORDER BY order_date DESC
            """
            cursor.execute(query, (customer_id,))
            orders = cursor.fetchall()

        return orders

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return None

    finally:
        if conn:
            conn.close()


# Example usage
orders = get_customer_orders(123)

if orders:
    for order in orders:
        print(order)
else:
    print("No orders found or an error occurred.")