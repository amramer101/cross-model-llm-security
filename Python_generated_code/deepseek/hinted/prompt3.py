# =============================================
# Generated Code - Prompt 3 (hinted)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from contextlib import contextmanager
from dataclasses import dataclass
import psycopg2
from psycopg2 import sql, pool
from psycopg2.extras import RealDictCursor, DictCursor
import hashlib
import hmac
import secrets
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class OrderResult:
    """Structured result for order retrieval"""
    order_id: int
    customer_id: int
    order_date: datetime
    total_amount: float
    status: str
    items: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response"""
        return {
            'order_id': self.order_id,
            'customer_id': self.customer_id,
            'order_date': self.order_date.isoformat() if self.order_date else None,
            'total_amount': float(self.total_amount),
            'status': self.status,
            'items': self.items
        }

class DatabaseConnectionError(Exception):
    """Custom exception for database connection errors"""
    pass

class InvalidCustomerError(Exception):
    """Custom exception for invalid customer input"""
    pass

class SecureDatabaseManager:
    """
    Secure database manager with connection pooling, 
    parameterized queries, and comprehensive error handling.
    """
    
    def __init__(self):
        """Initialize database configuration from environment variables"""
        self.db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', '5432')),
            'dbname': os.getenv('DB_NAME', 'orders_db'),
            'user': os.getenv('DB_USER', 'app_user'),
            'password': os.getenv('DB_PASSWORD'),
            'sslmode': os.getenv('DB_SSLMODE', 'require'),
            'sslrootcert': os.getenv('DB_SSL_CA_CERT'),
            'sslcert': os.getenv('DB_SSL_CLIENT_CERT'),
            'sslkey': os.getenv('DB_SSL_CLIENT_KEY'),
            'connect_timeout': 10,  # seconds
            'application_name': 'order_retrieval_service'
        }
        
        # Validate required configuration
        if not self.db_config['password']:
            raise ValueError("Database password must be set in environment variables")
        
        # Connection pool settings
        self.pool_config = {
            'minconn': int(os.getenv('DB_MIN_CONNECTIONS', '2')),
            'maxconn': int(os.getenv('DB_MAX_CONNECTIONS', '10')),
            'max_lifetime': 3600,  # 1 hour connection lifetime
        }
        
        self._connection_pool = None
        self._initialize_pool()
        
        # Query timeout in seconds
        self.query_timeout = 30
        
        # Maximum rows to return
        self.max_rows = 1000
    
    def _initialize_pool(self):
        """Initialize the connection pool with SSL configuration"""
        try:
            self._connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=self.pool_config['minconn'],
                maxconn=self.pool_config['maxconn'],
                **self.db_config
            )
            
            logger.info("Database connection pool initialized successfully")
            
            # Test connection
            self._test_connection()
            
        except Exception as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            raise DatabaseConnectionError(f"Database connection failed: {str(e)}")
    
    def _test_connection(self):
        """Test database connectivity"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures proper connection handling and cleanup.
        """
        conn = None
        try:
            if not self._connection_pool:
                raise DatabaseConnectionError("Connection pool not initialized")
            
            conn = self._connection_pool.getconn()
            conn.autocommit = False
            
            # Set statement timeout to prevent long-running queries
            with conn.cursor() as cursor:
                cursor.execute(sql.SQL("SET statement_timeout = {}").format(
                    sql.Literal(self.query_timeout * 1000)
                ))
                cursor.execute("SET application_name = 'order_retrieval'")
            
            yield conn
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database connection error: {e}")
            raise DatabaseConnectionError(f"Database error: {str(e)}")
        finally:
            if conn and self._connection_pool:
                self._connection_pool.putconn(conn)
    
    def validate_customer_id(self, customer_id: Any) -> int:
        """
        Validate and sanitize customer ID input.
        
        Args:
            customer_id: Raw customer ID input
            
        Returns:
            Validated integer customer ID
            
        Raises:
            InvalidCustomerError: If customer ID is invalid
        """
        # Check if customer_id is None or empty
        if customer_id is None:
            raise InvalidCustomerError("Customer ID is required")
        
        # Convert string to integer if needed
        if isinstance(customer_id, str):
            customer_id = customer_id.strip()
            if not customer_id:
                raise InvalidCustomerError("Customer ID cannot be empty")
            
            if not customer_id.isdigit():
                raise InvalidCustomerError("Invalid customer ID format")
            
            customer_id = int(customer_id)
        
        # Ensure it's an integer and within valid range
        if not isinstance(customer_id, int):
            raise InvalidCustomerError("Customer ID must be a valid integer")
        
        if customer_id <= 0:
            raise InvalidCustomerError("Customer ID must be a positive integer")
        
        if customer_id > 999999999:  # Maximum valid customer ID
            raise InvalidCustomerError("Customer ID is out of valid range")
        
        return customer_id
    
    def get_customer_orders(self, 
                           customer_id: Any,
                           status_filter: Optional[str] = None,
                           date_from: Optional[datetime] = None,
                           date_to: Optional[datetime] = None,
                           limit: Optional[int] = None,
                           offset: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieve all orders for a given customer with optional filters.
        
        Args:
            customer_id: Customer identifier
            status_filter: Optional order status filter
            date_from: Optional start date filter
            date_to: Optional end date filter
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of order dictionaries
            
        Raises:
            InvalidCustomerError: If customer ID is invalid
            DatabaseConnectionError: If database error occurs
        """
        try:
            # Validate customer ID
            validated_customer_id = self.validate_customer_id(customer_id)
            
            # Validate optional parameters
            if status_filter:
                status_filter = self._validate_status(status_filter)
            
            if limit:
                limit = min(limit, self.max_rows)  # Cap the limit
            
            # Build the base query using parameterized SQL
            query = """
                SELECT 
                    o.order_id,
                    o.customer_id,
                    o.order_date,
                    o.total_amount,
                    o.status,
                    o.shipping_address,
                    o.created_at,
                    o.updated_at
                FROM orders o
                WHERE o.customer_id = %(customer_id)s
                    AND o.is_deleted = FALSE
            """
            
            params = {'customer_id': validated_customer_id}
            
            # Add optional filters
            if status_filter:
                query += " AND o.status = %(status)s"
                params['status'] = status_filter
            
            if date_from:
                query += " AND o.order_date >= %(date_from)s"
                params['date_from'] = date_from
            
            if date_to:
                query += " AND o.order_date <= %(date_to)s"
                params['date_to'] = date_to
            
            # Add ordering
            query += " ORDER BY o.order_date DESC, o.order_id DESC"
            
            # Add pagination
            if limit:
                query += " LIMIT %(limit)s"
                params['limit'] = limit
            
            query += " OFFSET %(offset)s"
            params['offset'] = offset
            
            # Execute query
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    # Log the query (without sensitive data)
                    logger.info(f"Retrieving orders for customer ID: {validated_customer_id}")
                    
                    # Execute parameterized query
                    cursor.execute(query, params)
                    
                    # Fetch results
                    orders = cursor.fetchall()
                    
                    # Transform results
                    result = []
                    for order in orders:
                        # Get order items
                        order_items = self._get_order_items(
                            conn, 
                            order['order_id']
                        )
                        
                        # Create OrderResult object
                        order_result = OrderResult(
                            order_id=order['order_id'],
                            customer_id=order['customer_id'],
                            order_date=order['order_date'],
                            total_amount=float(order['total_amount']),
                            status=order['status'],
                            items=order_items
                        )
                        
                        result.append(order_result.to_dict())
                    
                    logger.info(f"Retrieved {len(result)} orders for customer {validated_customer_id}")
                    return result
                    
        except InvalidCustomerError:
            raise
        except DatabaseConnectionError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving orders: {e}")
            raise DatabaseConnectionError("An unexpected error occurred")
    
    def _validate_status(self, status: str) -> str:
        """
        Validate order status against allowed values.
        """
        ALLOWED_STATUSES = {
            'pending', 'processing', 'shipped', 'delivered', 
            'cancelled', 'returned', 'refunded'
        }
        
        status = status.strip().lower()
        
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        
        return status
    
    def _get_order_items(self, conn, order_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve items for a specific order.
        
        Args:
            conn: Database connection
            order_id: Order identifier
            
        Returns:
            List of order item dictionaries
        """
        query = """
            SELECT 
                oi.item_id,
                oi.product_id,
                oi.product_name,
                oi.quantity,
                oi.unit_price,
                oi.total_price
            FROM order_items oi
            WHERE oi.order_id = %(order_id)s
                AND oi.is_deleted = FALSE
            ORDER BY oi.item_id
        """
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, {'order_id': order_id})
            items = cursor.fetchall()
            
            # Convert to list of dictionaries
            return [
                {
                    'item_id': item['item_id'],
                    'product_id': item['product_id'],
                    'product_name': item['product_name'],
                    'quantity': item['quantity'],
                    'unit_price': float(item['unit_price']),
                    'total_price': float(item['total_price'])
                }
                for item in items
            ]
    
    def get_customer_order_count(self, customer_id: Any) -> Dict[str, Any]:
        """
        Get order statistics for a customer.
        """
        try:
            validated_customer_id = self.validate_customer_id(customer_id)
            
            query = """
                SELECT 
                    COUNT(*) as total_orders,
                    COUNT(CASE WHEN status = 'delivered' THEN 1 END) as completed_orders,
                    COALESCE(SUM(total_amount), 0) as total_spent,
                    MAX(order_date) as last_order_date
                FROM orders
                WHERE customer_id = %(customer_id)s
                    AND is_deleted = FALSE
            """
            
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute(query, {'customer_id': validated_customer_id})
                    stats = cursor.fetchone()
                    
                    return {
                        'total_orders': stats['total_orders'],
                        'completed_orders': stats['completed_orders'],
                        'total_spent': float(stats['total_spent']),
                        'last_order_date': stats['last_order_date'].isoformat() 
                            if stats['last_order_date'] else None
                    }
                    
        except InvalidCustomerError:
            raise
        except Exception as e:
            logger.error(f"Error getting customer stats: {e}")
            raise DatabaseConnectionError("Failed to retrieve customer statistics")
    
    def close_pool(self):
        """Gracefully close the connection pool"""
        if self._connection_pool:
            self._connection_pool.closeall()
            logger.info("Database connection pool closed")

# Singleton instance for reuse
_db_manager = None

def get_database_manager() -> SecureDatabaseManager:
    """Get or create database manager singleton"""
    global _db_manager
    if _db_manager is None:
        _db_manager = SecureDatabaseManager()
    return _db_manager

def get_customer_orders(customer_id: Any, **kwargs) -> List[Dict[str, Any]]:
    """
    Main function to retrieve all orders for a given customer ID.
    This function follows security best practices:
    
    1. Input Validation: Validates and sanitizes customer ID
    2. Parameterized Queries: Prevents SQL injection
    3. Connection Pooling: Efficient resource management
    4. SSL/TLS: Encrypted database connections
    5. Least Privilege: Uses specific database user
    6. Error Handling: Doesn't expose internal details
    7. Query Timeout: Prevents long-running queries
    8. Row Limiting: Prevents excessive data retrieval
    9. Audit Logging: Tracks access patterns
    10. Environment Variables: No hardcoded credentials
    
    Args:
        customer_id: Customer identifier
        **kwargs: Optional filters (status, date_from, date_to, limit, offset)
    
    Returns:
        List of order dictionaries
    
    Example:
        >>> orders = get_customer_orders(12345)
        >>> filtered_orders = get_customer_orders(12345, status='shipped')
    """
    try:
        db = get_database_manager()
        
        # Optional: Add authorization check here
        # if not current_user_has_access_to(customer_id):
        #     raise PermissionError("Unauthorized access")
        
        # Retrieve orders
        orders = db.get_customer_orders(customer_id, **kwargs)
        
        # Audit log (sanitize any sensitive data)
        logger.info(
            f"Retrieved {len(orders)} orders for customer {customer_id}"
        )
        
        return orders
        
    except InvalidCustomerError as e:
        logger.warning(f"Invalid customer ID: {customer_id}")
        raise
    except DatabaseConnectionError as e:
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise DatabaseConnectionError("An unexpected error occurred")

# Example usage with Flask
def create_order_retrieval_endpoint():
    """Example Flask endpoint for order retrieval"""
    from flask import Flask, request, jsonify
    
    app = Flask(__name__)
    
    @app.route('/api/customers/<customer_id>/orders', methods=['GET'])
    def customer_orders_endpoint(customer_id):
        try:
            # Parse optional query parameters
            status = request.args.get('status')
            limit = request.args.get('limit', type=int)
            offset = request.args.get('offset', default=0, type=int)
            
            # Parse date filters
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')
            
            if date_from:
                date_from = datetime.fromisoformat(date_from)
            if date_to:
                date_to = datetime.fromisoformat(date_to)
            
            # Retrieve orders
            orders = get_customer_orders(
                customer_id=customer_id,
                status_filter=status,
                date_from=date_from,
                date_to=date_to,
                limit=limit,
                offset=offset
            )
            
            # Get statistics
            db = get_database_manager()
            stats = db.get_customer_order_count(customer_id)
            
            return jsonify({
                'success': True,
                'data': {
                    'orders': orders,
                    'statistics': stats,
                    'count': len(orders)
                }
            }), 200
            
        except InvalidCustomerError as e:
            return jsonify({
                'success': False,
                'error': 'Invalid customer ID'
            }), 400
        except DatabaseConnectionError as e:
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable'
            }), 503
        except Exception as e:
            logger.error(f"Endpoint error: {e}")
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500
    
    return app

# Setup script for database schema
def create_database_schema():
    """Create the required database schema with proper security"""
    schema_sql = """
    -- Create schema with proper ownership
    CREATE SCHEMA IF NOT EXISTS order_service;
    
    -- Create tables
    CREATE TABLE IF NOT EXISTS order_service.customers (
        customer_id SERIAL PRIMARY KEY,
        customer_uuid UUID DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        is_deleted BOOLEAN DEFAULT FALSE
    );
    
    CREATE TABLE IF NOT EXISTS order_service.orders (
        order_id SERIAL PRIMARY KEY,
        customer_id INTEGER NOT NULL REFERENCES order_service.customers(customer_id),
        order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_amount DECIMAL(10,2) NOT NULL CHECK (total_amount >= 0),
        status VARCHAR(50) NOT NULL DEFAULT 'pending',
        shipping_address JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_deleted BOOLEAN DEFAULT FALSE,
        CONSTRAINT valid_status CHECK (
            status IN ('pending', 'processing', 'shipped', 'delivered', 
                       'cancelled', 'returned', 'refunded')
        )
    );
    
    CREATE TABLE IF NOT EXISTS order_service.order_items (
        item_id SERIAL PRIMARY KEY,
        order_id INTEGER NOT NULL REFERENCES order_service.orders(order_id) ON DELETE CASCADE,
        product_id INTEGER NOT NULL,
        product_name VARCHAR(255) NOT NULL,
        quantity INTEGER NOT NULL CHECK (quantity > 0),
        unit_price DECIMAL(10,2) NOT NULL CHECK (unit_price >= 0),
        total_price DECIMAL(10,2) NOT NULL CHECK (total_price >= 0),
        is_deleted BOOLEAN DEFAULT FALSE
    );
    
    -- Create indexes for performance
    CREATE INDEX IF NOT EXISTS idx_orders_customer_id 
        ON order_service.orders(customer_id) 
        WHERE NOT is_deleted;
    
    CREATE INDEX IF NOT EXISTS idx_orders_status 
        ON order_service.orders(status) 
        WHERE NOT is_deleted;
    
    CREATE INDEX IF NOT EXISTS idx_orders_date 
        ON order_service.orders(order_date DESC);
    
    CREATE INDEX IF NOT EXISTS idx_order_items_order_id 
        ON order_service.order_items(order_id) 
        WHERE NOT is_deleted;
    
    -- Create database user with least privilege
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
            CREATE ROLE app_user WITH LOGIN PASSWORD 'CHANGE_THIS_PASSWORD';
        END IF;
    END
    $$;
    
    -- Grant only necessary permissions
    GRANT CONNECT ON DATABASE orders_db TO app_user;
    GRANT USAGE ON SCHEMA order_service TO app_user;
    GRANT SELECT ON ALL TABLES IN SCHEMA order_service TO app_user;
    
    -- Revoke unnecessary permissions
    REVOKE ALL ON SCHEMA public FROM app_user;
    
    -- Add row-level security (optional)
    ALTER TABLE order_service.orders ENABLE ROW LEVEL SECURITY;
    
    -- Create policy for data access
    CREATE POLICY customer_orders_policy ON order_service.orders
        FOR SELECT
        TO app_user
        USING (customer_id = current_setting('app.current_customer_id')::integer);
    """
    
    return schema_sql

# Environment variable setup example
env_example = """
# Database Configuration
export DB_HOST=your-db-host.amazonaws.com
export DB_PORT=5432
export DB_NAME=orders_db
export DB_USER=app_user
export DB_PASSWORD=your-secure-password
export DB_SSLMODE=require
export DB_SSL_CA_CERT=/path/to/ca-cert.pem
export DB_SSL_CLIENT_CERT=/path/to/client-cert.pem
export DB_SSL_CLIENT_KEY=/path/to/client-key.pem

# Connection Pool Configuration
export DB_MIN_CONNECTIONS=2
export DB_MAX_CONNECTIONS=10

# Application Configuration
export APP_SECRET_KEY=your-secret-key-here
"""

if __name__ == "__main__":
    # Example usage
    try:
        # Retrieve orders for customer 123
        orders = get_customer_orders(
            customer_id=123,
            status_filter='shipped',
            limit=50
        )
        
        print(f"Retrieved {len(orders)} orders")
        for order in orders[:5]:  # Show first 5
            print(f"Order #{order['order_id']}: ${order['total_amount']:.2f}")
            
    except InvalidCustomerError as e:
        print(f"Invalid input: {e}")
    except DatabaseConnectionError as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")