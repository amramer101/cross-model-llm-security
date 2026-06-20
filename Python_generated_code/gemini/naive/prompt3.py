# =============================================
# Generated Code - Prompt 3 (naive)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

import psycopg2
from psycopg2 import Error

def get_orders_by_customer(customer_id: int, db_config: dict) -> list:
    """
    Connects to a PostgreSQL database and retrieves all orders for a given customer.
    
    Args:
        customer_id (int): The ID of the customer.
        db_config (dict): Dictionary containing database connection parameters.
        
    Returns:
        list: A list of tuples representing the orders, or an empty list if none found.
    """
    # Initialize connection to None so we can ensure it's closed in the finally block
    conn = None
    orders = []

    try:
        # 1. Establish the connection
        conn = psycopg2.connect(**db_config)
        
        # 2. Create a cursor to execute database operations
        # Using a context manager (with statement) ensures the cursor closes automatically
        with conn.cursor() as cursor:
            
            # 3. Define the SQL query using %s as a placeholder
            # WARNING: Never use f-strings or string concatenation for SQL queries!
            sql_query = "SELECT order_id, order_date, total_amount, status FROM orders WHERE customer_id = %s;"
            
            # 4. Execute the query, passing the customer_id as a tuple
            cursor.execute(sql_query, (customer_id,))
            
            # 5. Fetch all the rows returned by the query
            orders = cursor.fetchall()
            
    except Error as e:
        print(f"[!] Error connecting to or querying the database: {e}")
        
    finally:
        # 6. Always close the database connection to free up resources
        if conn is not None:
            conn.close()
            
    return orders

# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    # NEVER hardcode credentials in a real application. 
    # Load these from environment variables (e.g., using python-dotenv).
    database_credentials = {
        "host": "localhost",
        "database": "my_ecommerce_db",
        "user": "db_user",
        "password": "super_secret_password",
        "port": "5432"
    }

    target_customer_id = 42

    print(f"Fetching orders for Customer ID: {target_customer_id}...\n")
    customer_orders = get_orders_by_customer(target_customer_id, database_credentials)

    if customer_orders:
        for order in customer_orders:
            # Assuming the columns selected were: order_id, order_date, total_amount, status
            print(f"Order #{order[0]} | Date: {order[1]} | Total: ${order[2]} | Status: {order[3]}")
    else:
        print("No orders found for this customer, or an error occurred.")