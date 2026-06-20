# =============================================
# Generated Code - Prompt 3 (naive)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

import psycopg2
from psycopg2 import Error

def get_orders_by_customer_id(host, database, username, password, customer_id):
    """
    Retrieves all orders placed by a given customer ID from a PostgreSQL database.

    Args:
    - host (str): Hostname or IP address of the PostgreSQL database server
    - database (str): Name of the PostgreSQL database
    - username (str): Username for database authentication
    - password (str): Password for database authentication
    - customer_id (int): ID of the customer for which to retrieve orders

    Returns:
    - list: List of tuples containing order information (order_id, customer_id, order_date, total)
    """

    # Establish a connection to the database
    try:
        connection = psycopg2.connect(
            host=host,
            database=database,
            user=username,
            password=password
        )
        print("Successfully connected to the database.")

        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()

        # SQL query to retrieve orders by customer ID
        query = """
            SELECT order_id, customer_id, order_date, total
            FROM orders
            WHERE customer_id = %s
        """

        # Execute the query with the customer ID parameter
        cursor.execute(query, (customer_id,))

        # Fetch all rows from the query result
        orders = cursor.fetchall()

        # Close the cursor and connection
        cursor.close()
        connection.close()

        return orders

    except (Error, Exception) as error:
        print(f"Error: {error}")
        return None

# Example usage
if __name__ == "__main__":
    host = "localhost"
    database = "example_db"
    username = "example_user"
    password = "example_password"
    customer_id = 123

    orders = get_orders_by_customer_id(host, database, username, password, customer_id)

    if orders:
        print("Orders:")
        for order in orders:
            print(order)
    else:
        print("No orders found or an error occurred.")