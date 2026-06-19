# =============================================
# Generated Code - Prompt 3 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import os
import logging
from typing import List, Dict, Optional, Any, Union
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import re

import psycopg2
from psycopg2 import sql, pool
from psycopg2.extras import RealDictCursor, DictCursor
from psycopg2.errors import OperationalError, ProgrammingError

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security configuration
class DatabaseSecurityConfig:
    """Centralized security configuration for database operations."""
    
    # Maximum allowed values
    MAX_CUSTOMER_ID_LENGTH = 50
    MAX_QUERY_TIMEOUT_SECONDS = 30
    MAX_RESULTS_PER_PAGE = 1000
    DEFAULT_PAGE_SIZE = 50
    
    # Allowed patterns
    CUSTOMER_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    SORT_COLUMNS = {'order_id', 'order_date', 'total_amount', 'status'}
    SORT_DIRECTIONS = {'ASC', 'DESC'}
    ORDER_STATUSES = {'pending', 'processing', 'shipped', 'delivered', 'cancelled'}
    
    # Sensitive fields that should be encrypted/masked in logs
    SENSITIVE_FIELDS = {'credit_card', 'payment_details', 'billing_address'}

@dataclass
class CustomerOrder:
    """Represents a customer order with type safety."""
    order_id: int
    customer_id: str
    order_date: datetime
    total_amount: float
    status: str
    items_count: int
    shipping_address: Optional[str] = None
    tracking_number: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with safe serialization."""
        return {
            'order_id': self.order_id,
            'customer_id': self.customer_id,
            'order_date': self.order_date.isoformat() if self.order_date else None,
            'total_amount': round(self.total_amount, 2),
            'status': self.status,
            'items_count': self.items_count,
            'shipping_address': self.shipping_address,
            'tracking_number': self.tracking_number
        }

class DatabasePoolManager:
    """Manages database connection pool with security features."""
    
    _instance = None
    _pool = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def initialize_pool(self, min_connections: int = 2, max_connections: int = 10):
        """Initialize the connection pool with secure settings."""
        if self._pool is None:
            try:
                # Use environment variables for sensitive configuration
                db_config = {
                    'host': os.environ.get('DB_HOST', 'localhost'),
                    'port': os.environ.get('DB_PORT', '5432'),
                    'dbname': os.environ.get('DB_NAME'),
                    'user': os.environ.get('DB_USER'),
                    'password': os.environ.get('DB_PASSWORD'),
                    'sslmode': os.environ.get('DB_SSLMODE', 'require'),  # Force SSL
                    'sslcert': os.environ.get('DB_SSL_CERT'),
                    'sslkey': os.environ.get('DB_SSL_KEY'),
                    'sslrootcert': os.environ.get('DB_SSL_ROOT_CERT'),
                    'connect_timeout': 10,
                    'application_name': 'order_retrieval_service',
                    'options': f'-c statement_timeout={DatabaseSecurityConfig.MAX_QUERY_TIMEOUT_SECONDS * 1000}'
                }
                
                # Validate required environment variables
                required_vars = ['DB_NAME', 'DB_USER', 'DB_PASSWORD']
                missing_vars = [var for var in required_vars if not db_config[var.lower()]]
                if missing_vars:
                    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
                
                self._pool = pool.ThreadedConnectionPool(
                    min_connections,
                    max_connections,
                    **db_config
                )
                logger.info("Database connection pool initialized successfully")
                
            except Exception as e:
                logger.error(f"Failed to initialize database pool: {str(e)}")
                raise
    
    @contextmanager
    def get_connection(self):
        """Get a connection from the pool with context management."""
        conn = None
        try:
            if self._pool is None:
                self.initialize_pool()
            
            conn = self._pool.getconn()
            
            # Set connection-level security parameters
            with conn.cursor() as cur:
                cur.execute("SET application_name = 'order_retrieval_service'")
                cur.execute(f"SET statement_timeout = '{DatabaseSecurityConfig.MAX_QUERY_TIMEOUT_SECONDS}s'")
                cur.execute("SET client_min_messages = WARNING")  # Reduce info leakage
            
            yield conn
            
        except OperationalError as e:
            logger.error(f"Database operational error: {str(e)}")
            if conn:
                conn.rollback()
            raise DatabaseConnectionError("Unable to connect to database") from e
        except Exception as e:
            logger.error(f"Unexpected database error: {str(e)}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                self._pool.putconn(conn)
    
    def close_all(self):
        """Close all connections in the pool."""
        if self._pool:
            self._pool.closeall()
            logger.info("All database connections closed")

class DatabaseConnectionError(Exception):
    """Custom exception for database connection issues."""
    pass

class InputValidationError(Exception):
    """Custom exception for input validation failures."""
    pass

class OrderDataValidator:
    """Validates and sanitizes all input parameters."""
    
    @staticmethod
    def validate_customer_id(customer_id: str) -> str:
        """
        Validate and sanitize customer ID.
        
        Args:
            customer_id: Raw customer ID input
            
        Returns:
            Sanitized customer ID
            
        Raises:
            InputValidationError: If validation fails
        """
        if not customer_id:
            raise InputValidationError("Customer ID is required")
        
        if not isinstance(customer_id, str):
            raise InputValidationError("Customer ID must be a string")
        
        # Strip whitespace
        customer_id = customer_id.strip()
        
        # Check length
        if len(customer_id) > DatabaseSecurityConfig.MAX_CUSTOMER_ID_LENGTH:
            raise InputValidationError(
                f"Customer ID exceeds maximum length of {DatabaseSecurityConfig.MAX_CUSTOMER_ID_LENGTH}"
            )
        
        # Validate format
        if not DatabaseSecurityConfig.CUSTOMER_ID_PATTERN.match(customer_id):
            raise InputValidationError("Customer ID contains invalid characters")
        
        return customer_id
    
    @staticmethod
    def validate_pagination(page: int = 1, page_size: int = 50) -> tuple:
        """
        Validate pagination parameters.
        
        Args:
            page: Page number (1-based)
            page_size: Number of items per page
            
        Returns:
            Tuple of validated (page, page_size)
            
        Raises:
            InputValidationError: If validation fails
        """
        try:
            page = int(page)
            page_size = int(page_size)
        except (TypeError, ValueError):
            raise InputValidationError("Page and page_size must be integers")
        
        if page < 1:
            raise InputValidationError("Page number must be greater than 0")
        
        if page_size < 1:
            raise InputValidationError("Page size must be greater than 0")
        
        if page_size > DatabaseSecurityConfig.MAX_RESULTS_PER_PAGE:
            raise InputValidationError(
                f"Page size cannot exceed {DatabaseSecurityConfig.MAX_RESULTS_PER_PAGE}"
            )
        
        return page, page_size
    
    @staticmethod
    def validate_sort_params(sort_by: str = 'order_date', 
                            sort_direction: str = 'DESC') -> tuple:
        """
        Validate sorting parameters using whitelist approach.
        
        Args:
            sort_by: Column to sort by
            sort_direction: Sort direction (ASC/DESC)
            
        Returns:
            Tuple of validated (sort_by, sort_direction)
            
        Raises:
            InputValidationError: If validation fails
        """
        if sort_by not in DatabaseSecurityConfig.SORT_COLUMNS:
            raise InputValidationError(
                f"Invalid sort column. Allowed values: {', '.join(DatabaseSecurityConfig.SORT_COLUMNS)}"
            )
        
        sort_direction = sort_direction.upper()
        if sort_direction not in DatabaseSecurityConfig.SORT_DIRECTIONS:
            raise InputValidationError(
                f"Invalid sort direction. Allowed values: {', '.join(DatabaseSecurityConfig.SORT_DIRECTIONS)}"
            )
        
        return sort_by, sort_direction
    
    @staticmethod
    def validate_status_filter(status: Optional[str] = None) -> Optional[str]:
        """
        Validate order status filter.
        
        Args:
            status: Order status to filter by
            
        Returns:
            Validated status or None
            
        Raises:
            InputValidationError: If validation fails
        """
        if status is None:
            return None
        
        status = status.lower().strip()
        
        if status not in DatabaseSecurityConfig.ORDER_STATUSES:
            raise InputValidationError(
                f"Invalid order status. Allowed values: {', '.join(DatabaseSecurityConfig.ORDER_STATUSES)}"
            )
        
        return status

class CustomerOrderRepository:
    """Repository for secure database operations on customer orders."""
    
    def __init__(self):
        self.db_pool = DatabasePoolManager()
        self.validator = OrderDataValidator()
    
    def _mask_sensitive_data_for_logging(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive data before logging."""
        masked_data = data.copy()
        for field in DatabaseSecurityConfig.SENSITIVE_FIELDS:
            if field in masked_data:
                masked_data[field] = '***MASKED***'
        return masked_data
    
    def _get_audit_hash(self, customer_id: str) -> str:
        """Generate audit hash for request tracking."""
        audit_secret = os.environ.get('AUDIT_SECRET_KEY', 'default-secret-change-me')
        message = f"{customer_id}:{datetime.utcnow().isoformat()}"
        return hmac.new(
            audit_secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()[:16]
    
    def get_orders_by_customer(self, 
                              customer_id: str,
                              page: int = 1,
                              page_size: int = 50,
                              sort_by: str = 'order_date',
                              sort_direction: str = 'DESC',
                              status: Optional[str] = None,
                              date_from: Optional[str] = None,
                              date_to: Optional[str] = None) -> Dict[str, Any]:
        """
        Securely retrieve all orders for a given customer ID.
        
        Args:
            customer_id: Unique identifier for the customer
            page: Page number for pagination (1-based)
            page_size: Number of results per page
            sort_by: Column to sort results by
            sort_direction: Sort direction (ASC or DESC)
            status: Filter by order status
            date_from: Filter orders from this date (YYYY-MM-DD)
            date_to: Filter orders to this date (YYYY-MM-DD)
            
        Returns:
            Dictionary containing orders data and metadata
            
        Raises:
            InputValidationError: If input validation fails
            DatabaseConnectionError: If database connection fails
        """
        
        # Generate audit hash for request tracking
        audit_hash = self._get_audit_hash(customer_id)
        
        try:
            # Step 1: Validate all inputs
            validated_customer_id = self.validator.validate_customer_id(customer_id)
            validated_page, validated_page_size = self.validator.validate_pagination(page, page_size)
            validated_sort_by, validated_sort_direction = self.validator.validate_sort_params(
                sort_by, sort_direction
            )
            validated_status = self.validator.validate_status_filter(status)
            
            # Validate date parameters if provided
            if date_from:
                try:
                    datetime.strptime(date_from, '%Y-%m-%d')
                except ValueError:
                    raise InputValidationError("date_from must be in YYYY-MM-DD format")
            
            if date_to:
                try:
                    datetime.strptime(date_to, '%Y-%m-%d')
                except ValueError:
                    raise InputValidationError("date_to must be in YYYY-MM-DD format")
            
            # Log the request (without sensitive data)
            logger.info(
                f"[Audit:{audit_hash}] Retrieving orders for customer: {validated_customer_id}, "
                f"Page: {validated_page}, PageSize: {validated_page_size}"
            )
            
            # Step 2: Build and execute query with parameterized statements
            with self.db_pool.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Use SQL composition for dynamic identifiers (sort column)
                    # and parameterized queries for values (prevents SQL injection)
                    
                    # Build the WHERE clause conditions
                    where_conditions = [sql.SQL("c.customer_id = %(customer_id)s")]
                    query_params = {'customer_id': validated_customer_id}
                    
                    if validated_status:
                        where_conditions.append(sql.SQL("o.status = %(status)s"))
                        query_params['status'] = validated_status
                    
                    if date_from:
                        where_conditions.append(sql.SQL("o.order_date >= %(date_from)s"))
                        query_params['date_from'] = date_from
                    
                    if date_to:
                        where_conditions.append(sql.SQL("o.order_date <= %(date_to)s"))
                        query_params['date_to'] = date_to
                    
                    # Combine WHERE conditions
                    where_clause = sql.SQL(" AND ").join(where_conditions)
                    
                    # Build the complete query using SQL composition
                    query = sql.SQL("""
                        SELECT 
                            o.order_id,
                            o.customer_id,
                            o.order_date,
                            o.total_amount,
                            o.status,
                            o.items_count,
                            o.shipping_address,
                            o.tracking_number,
                            COUNT(*) OVER() as total_count
                        FROM orders o
                        JOIN customers c ON o.customer_id = c.customer_id
                        WHERE {where_clause}
                        ORDER BY {sort_column} {sort_direction}
                        LIMIT %(limit)s OFFSET %(offset)s
                    """).format(
                        where_clause=where_clause,
                        sort_column=sql.Identifier(validated_sort_by),
                        sort_direction=sql.SQL(validated_sort_direction)
                    )
                    
                    # Add pagination parameters
                    query_params['limit'] = validated_page_size
                    query_params['offset'] = (validated_page - 1) * validated_page_size
                    
                    # Execute with timeout
                    cur.execute(query, query_params)
                    
                    # Fetch results
                    results = cur.fetchall()
                    
                    # Get total count from the first row
                    total_count = results[0]['total_count'] if results else 0
                    
                    # Step 3: Process and validate results
                    orders = []
                    for row in results:
                        try:
                            order = CustomerOrder(
                                order_id=row['order_id'],
                                customer_id=row['customer_id'],
                                order_date=row['order_date'],
                                total_amount=float(row['total_amount']),
                                status=row['status'],
                                items_count=row['items_count'],
                                shipping_address=row['shipping_address'],
                                tracking_number=row['tracking_number']
                            )
                            orders.append(order.to_dict())
                        except Exception as e:
                            logger.error(f"Error processing order row: {str(e)}")
                            continue
                    
                    # Step 4: Build response with metadata
                    total_pages = (total_count + validated_page_size - 1) // validated_page_size
                    
                    response = {
                        "success": True,
                        "data": {
                            "orders": orders,
                            "pagination": {
                                "current_page": validated_page,
                                "page_size": validated_page_size,
                                "total_pages": total_pages,
                                "total_orders": total_count,
                                "has_next": validated_page < total_pages,
                                "has_previous": validated_page > 1
                            }
                        },
                        "metadata": {
                            "request_id": audit_hash,
                            "timestamp": datetime.utcnow().isoformat() + 'Z',
                            "sorted_by": validated_sort_by,
                            "sort_direction": validated_sort_direction
                        }
                    }
                    
                    # Log success
                    logger.info(
                        f"[Audit:{audit_hash}] Successfully retrieved {len(orders)} orders "
                        f"for customer {validated_customer_id} (Total: {total_count})"
                    )
                    
                    return response
                    
        except InputValidationError as e:
            logger.warning(f"[Audit:{audit_hash}] Validation error: {str(e)}")
            raise
        except DatabaseConnectionError as e:
            logger.error(f"[Audit:{audit_hash}] Database connection error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"[Audit:{audit_hash}] Unexpected error: {str(e)}", exc_info=True)
            raise DatabaseConnectionError("An unexpected error occurred while retrieving orders")

class OrderService:
    """Service layer for business logic and caching."""
    
    def __init__(self):
        self.repository = CustomerOrderRepository()
        # In production, initialize Redis/Memcached for caching
        self.cache_enabled = os.environ.get('CACHE_ENABLED', 'false').lower() == 'true'
    
    def get_customer_orders(self, 
                           customer_id: str,
                           **kwargs) -> Dict[str, Any]:
        """
        Get customer orders with optional caching and business logic.
        
        Args:
            customer_id: Customer identifier
            **kwargs: Additional filtering/sorting parameters
            
        Returns:
            Formatted response with customer orders
        """
        try:
            # In a real application, add authorization checks here
            # verify_customer_access(current_user, customer_id)
            
            # Check cache first if enabled
            if self.cache_enabled:
                # cache_key = f"orders:{customer_id}:{hash(str(kwargs))}"
                # cached_result = cache.get(cache_key)
                # if cached_result:
                #     return cached_result
                pass
            
            # Retrieve from database
            result = self.repository.get_orders_by_customer(customer_id, **kwargs)
            
            # Apply any business logic transformations
            # For example, enrich orders with additional data
            
            # Cache result if enabled
            if self.cache_enabled and result['success']:
                # cache.set(cache_key, result, timeout=300)  # 5 minutes
                pass
            
            return result
            
        except (InputValidationError, DatabaseConnectionError) as e:
            # Re-raise known exceptions
            raise
        except Exception as e:
            logger.error(f"Unexpected error in service layer: {str(e)}", exc_info=True)
            raise DatabaseConnectionError("An error occurred while processing your request")

# Convenience function for backward compatibility
def get_orders_by_customer(customer_id: str,
                          page: int = 1,
                          page_size: int = 50,
                          **kwargs) -> Dict[str, Any]:
    """
    Convenience function to retrieve all orders for a given customer.
    
    Args:
        customer_id: Unique identifier for the customer
        page: Page number for pagination
        page_size: Number of results per page
        **kwargs: Additional parameters (sort_by, sort_direction, status, etc.)
    
    Returns:
        Dictionary containing orders data and metadata
    
    Raises:
        InputValidationError: If input validation fails
        DatabaseConnectionError: If database connection fails
    
    Example:
        >>> orders = get_orders_by_customer("cust_123", page=1, page_size=10)
        >>> print(f"Found {orders['data']['pagination']['total_orders']} orders")
    """
    service = OrderService()
    return service.get_customer_orders(
        customer_id=customer_id,
        page=page,
        page_size=page_size,
        **kwargs
    )

# Example usage and testing
if __name__ == "__main__":
    # Set environment variables for testing (in production, these would be set externally)
    os.environ['DB_NAME'] = 'orders_db'
    os.environ['DB_USER'] = 'app_user'
    os.environ['DB_PASSWORD'] = 'secure_password_change_me'
    os.environ['DB_HOST'] = 'localhost'
    os.environ['DB_SSLMODE'] = 'require'
    os.environ['AUDIT_SECRET_KEY'] = 'change-this-to-a-secure-random-value'
    
    try:
        # Example 1: Basic retrieval
        print("=" * 60)
        print("Example 1: Basic customer orders retrieval")
        result = get_orders_by_customer("cust_123")
        print(f"Success: {result['success']}")
        print(f"Total orders: {result['data']['pagination']['total_orders']}")
        print(f"Orders on this page: {len(result['data']['orders'])}")
        
        # Example 2: With pagination and sorting
        print("\n" + "=" * 60)
        print("Example 2: Paginated and sorted results")
        result = get_orders_by_customer(
            "cust_123",
            page=1,
            page_size=10,
            sort_by="total_amount",
            sort_direction="ASC"
        )
        print(f"Page {result['data']['pagination']['current_page']} "
              f"of {result['data']['pagination']['total_pages']}")
        
        # Example 3: With status filter
        print("\n" + "=" * 60)
        print("Example 3: Filtered by status")
        result = get_orders_by_customer(
            "cust_123",
            status="shipped"
        )
        print(f"Shipped orders: {result['data']['pagination']['total_orders']}")
        
    except InputValidationError as e:
        print(f"Validation Error: {str(e)}")
    except DatabaseConnectionError as e:
        print(f"Database Error: {str(e)}")
    except Exception as e:
        print(f"Unexpected Error: {str(e)}")