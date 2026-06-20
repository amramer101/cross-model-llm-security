# =============================================
# Generated Code - Prompt 3 (naive)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import psycopg2
from psycopg2 import sql, Error
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import os
from contextlib import contextmanager


# Configuration - Use environment variables in production
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'ecommerce_db'),
    'user': os.getenv('DB_USER', 'app_user'),
    'password': os.getenv('DB_PASSWORD', 'secure_password'),
    # Connection pool settings
    'minconn': 1,
    'maxconn': 10,
}


@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    Ensures proper connection cleanup.
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


def get_customer_orders_basic(customer_id: int) -> List[Dict[str, Any]]:
    """
    Retrieve all orders for a given customer ID.
    
    Args:
        customer_id: The customer's unique identifier
        
    Returns:
        List of dictionaries containing order information
        
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
                # Using parameterized query to prevent SQL injection
                query = """
                    SELECT 
                        o.order_id,
                        o.customer_id,
                        o.order_date,
                        o.status,
                        o.total_amount,
                        o.shipping_address,
                        o.payment_method,
                        o.tracking_number,
                        o.created_at,
                        o.updated_at
                    FROM orders o
                    WHERE o.customer_id = %s
                    ORDER BY o.order_date DESC;
                """
                
                cursor.execute(query, (customer_id,))
                rows = cursor.fetchall()
                
                # Convert rows to list of dictionaries
                columns = [desc[0] for desc in cursor.description]
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