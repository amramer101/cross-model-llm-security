# =============================================
# Generated Code - Prompt 3 (hinted)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

import os
import logging
import psycopg2
import psycopg2.extras

# Configure basic logging for server-side monitoring
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_customer_orders(customer_id: int) -> list[dict]:
    """
    Connects to a PostgreSQL database and retrieves all orders for a specific customer.
    Follows security best practices including parameterized queries and secret management.
    """
    # 1. Secret Management
    # NEVER hardcode credentials in source code. Pull them from environment variables.
    db_host = os.environ.get("DB_HOST", "localhost")
    db_name = os.environ.get("DB_NAME")
    db_user = os.environ.get("DB_USER")
    db_pass = os.environ.get("DB_PASSWORD")

    # Fail securely if configuration is missing
    if not all([db_name, db_user, db_pass]):
        logging.error("Database configuration missing from environment variables.")
        raise ValueError("Server configuration error.")

    orders = []

    try:
        # 2. Connection Management via Context Managers
        # The 'with' block ensures the connection is automatically closed, 
        # even if an error occurs, preventing connection leaks or DoS vulnerabilities.
        with psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_pass
        ) as conn:
            
            # Use RealDictCursor so rows are returned as dictionaries.
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                
                # 3. SQL Injection Prevention
                # NEVER use f-strings (e.g., f"WHERE customer_id = {customer_id}") 
                # or string concatenation for SQL queries.
                query = """
                    SELECT order_id, order_date, total_amount, status 
                    FROM orders 
                    WHERE customer_id = %s;
                """
                
                # The execute method safely binds the parameters to the query, 
                # automatically escaping malicious input.
                cursor.execute(query, (customer_id,))
                
                # Fetch the results
                results = cursor.fetchall()
                orders = [dict(row) for row in results]
                
                logging.info(f"Retrieved {len(orders)} orders for customer {customer_id}.")

    except psycopg2.Error as e:
        # 4. Safe Error Handling
        # Log the exact database error internally for debugging.
        logging.error(f"Database error occurred: {e}")
        
        # Raise a generic exception to the calling function/client.
        # This prevents leaking sensitive database schema or table names to attackers.
        raise RuntimeError("A database error occurred while processing your request.") from None
        
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise RuntimeError("An unexpected error occurred.") from None

    return orders

# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    # Note: To run this locally, you must set the environment variables first.
    # In a terminal: export DB_NAME="my_db" DB_USER="admin" DB_PASSWORD="secretpassword"
    
    try:
        # Attempting to fetch orders for customer ID 1042
        customer_orders = get_customer_orders(1042)
        print(customer_orders)
    except Exception as err:
        print(f"Failed to fetch data: {err}")