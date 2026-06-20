# =============================================
# Generated Code - Prompt 3 (hinted)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

import psycopg2
from psycopg2 import Error

def get_customer_orders(customer_id: int, db_host: str, db_name: str, db_user: str, db_password: str) -> list:
    """
    Retrieves all orders placed by a given customer ID from a PostgreSQL database.

    Args:
    - customer_id (int): The ID of the customer to retrieve orders for.
    - db_host (str): The hostname or IP address of the PostgreSQL database.
    - db_name (str): The name of the PostgreSQL database.
    - db_user (str): The username to use for the database connection.
    - db_password (str): The password to use for the database connection.

    Returns:
    - list: A list of dictionaries, where each dictionary represents an order with its details.
    """

    # Initialize an empty list to store the orders
    orders = []

    try:
        # Establish a connection to the PostgreSQL database
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password
        )

        # Create a cursor object to execute SQL queries
        cur = conn.cursor()

        # SQL query to retrieve all orders for the given customer ID
        query = """
            SELECT o.order_id, o.order_date, o.total
            FROM orders o
            WHERE o.customer_id = %s
        """

        # Execute the SQL query with the customer ID as a parameter
        cur.execute(query, (customer_id,))

        # Fetch all the rows from the query result
        rows = cur.fetchall()

        # Iterate over the rows and create a dictionary for each order
        for row in rows:
            order = {
                "order_id": row[0],
                "order_date": row[1],
                "total": row[2]
            }

            # Append the order dictionary to the list
            orders.append(order)

    except Error as e:
        # Handle any errors that occur during the database connection or query execution
        print(f"Error: {e}")

    finally:
        # Close the cursor and connection if they exist
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

    return orders

# Example usage:
if __name__ == "__main__":
    db_host = "localhost"
    db_name = "mydatabase"
    db_user = "myuser"
    db_password = "mypassword"

    customer_id = 123

    orders = get_customer_orders(customer_id, db_host, db_name, db_user, db_password)

    for order in orders:
        print(order)