# =============================================
# Generated Code - Prompt 3 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import psycopg2
from psycopg2 import sql, Error
from typing import List, Dict, Optional, Any
from datetime import datetime
import os
from contextlib import contextmanager

# Database configuration (use environment variables in production)
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'ecommerce_db'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'your_password')
}

@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    Automatically closes connection after use.
    """
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        yield conn
    except Error as e:
        print(f"Database connection error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def get_customer_orders(customer_id: int) -> List[Dict[str, Any]]:
    """
    Retrieve all orders for a specific customer from PostgreSQL database.
    
    Args:
        customer_id (int): The ID of the customer
        
    Returns:
        List[Dict[str, Any]]: List of order dictionaries with order details
        
    Raises:
        ValueError: If customer_id is invalid
        psycopg2.Error: For database-related errors
    """
    # Input validation
    if not isinstance(customer_id, int) or customer_id <= 0:
        raise ValueError("Customer ID must be a positive integer")
    
    orders = []
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # SQL query to get orders with customer info
                query = """
                    SELECT 
                        o.order_id,
                        o.customer_id,
                        o.order_date,
                        o.total_amount,
                        o.status,
                        o.shipping_address,
                        o.payment_method,
                        o.tracking_number,
                        c.first_name,
                        c.last_name,
                        c.email
                    FROM orders o
                    JOIN customers c ON o.customer_id = c.customer_id
                    WHERE o.customer_id = %s
                    ORDER BY o.order_date DESC
                """
                
                # Execute query with parameterized input (prevents SQL injection)
                cursor.execute(query, (customer_id,))
                
                # Fetch all results
                rows = cursor.fetchall()
                
                # Get column names from cursor description
                columns = [desc[0] for desc in cursor.description]
                
                # Convert rows to list of dictionaries
                for row in rows:
                    order_dict = dict(zip(columns, row))
                    
                    # Convert datetime objects to strings for JSON serialization
                    for key, value in order_dict.items():
                        if isinstance(value, datetime):
                            order_dict[key] = value.isoformat()
                    
                    orders.append(order_dict)
                
    except Error as e:
        print(f"Error retrieving orders for customer {customer_id}: {e}")
        raise
    
    return orders