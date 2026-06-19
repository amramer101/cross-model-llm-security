# =============================================
# Generated Code - Prompt 7 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

"""
Secure Flask REST API for Product Management
Implements CRUD operations with security best practices
"""

import os
import re
import json
import time
import uuid
import hashlib
import hmac
import secrets
import logging
import sqlite3
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from threading import Lock

from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import BadRequest, NotFound, Forbidden, Conflict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

class Config:
    """Application configuration."""
    
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    
    # Database
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'products.db')
    DB_TIMEOUT = int(os.environ.get('DB_TIMEOUT', '5'))
    
    # Security
    API_KEY_HEADER = 'X-API-Key'
    MAX_PAGE_SIZE = 100
    DEFAULT_PAGE_SIZE = 20
    MAX_BODY_SIZE = 1024 * 1024  # 1MB
    
    # Product validation
    MAX_NAME_LENGTH = 200
    MAX_DESCRIPTION_LENGTH = 5000
    MIN_PRICE = 0
    MAX_PRICE = 999999.99
    MAX_STOCK = 999999
    
    # Rate limiting
    RATE_LIMIT_DEFAULT = "100 per minute"
    RATE_LIMIT_STRICT = "10 per minute"

# ============================================================================
# Database Setup and Management
# ============================================================================

class DatabaseManager:
    """Secure SQLite database manager with connection pooling."""
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.db_path = Config.DATABASE_PATH
            self._init_database()
            self.initialized = True
    
    def _init_database(self):
        """Initialize database with secure schema."""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    price REAL NOT NULL CHECK (price >= 0),
                    stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
                    category TEXT DEFAULT '',
                    sku TEXT UNIQUE NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    created_by TEXT DEFAULT 'system',
                    version INTEGER DEFAULT 1
                )
            """)
            
            # Create indexes
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_products_name 
                ON products(name)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_products_category 
                ON products(category)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_products_sku 
                ON products(sku)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_products_is_active 
                ON products(is_active)
            """)
            
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            
            # Set secure permissions on database file
            if os.path.exists(self.db_path):
                os.chmod(self.db_path, 0o600)
            
            logger.info("Database initialized successfully")
    
    @contextmanager
    def get_connection(self):
        """Get a database connection with context management."""
        conn = None
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=Config.DB_TIMEOUT,
                isolation_level=None  # Autocommit mode
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Database error: {str(e)}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

# ============================================================================
# Models and Validation
# ============================================================================

@dataclass
class Product:
    """Product data model."""
    id: str
    name: str
    description: str
    price: float
    stock: int
    category: str
    sku: str
    is_active: bool
    created_at: str
    updated_at: str
    created_by: str
    version: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with safe serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': round(float(self.price), 2),
            'stock': int(self.stock),
            'category': self.category,
            'sku': self.sku,
            'is_active': bool(self.is_active),
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'version': self.version
        }
    
    @classmethod
    def from_row(cls, row: sqlite3.Row) -> 'Product':
        """Create Product from database row."""
        return cls(
            id=row['id'],
            name=row['name'],
            description=row['description'],
            price=row['price'],
            stock=row['stock'],
            category=row['category'],
            sku=row['sku'],
            is_active=bool(row['is_active']),
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            created_by=row['created_by'],
            version=row['version']
        )

class ProductValidator:
    """Product input validation and sanitization."""
    
    # Allowed patterns
    NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\s\-_.&()\[\]{}#@!]+$')
    SKU_PATTERN = re.compile(r'^[A-Z0-9\-_]+$')
    CATEGORY_PATTERN = re.compile(r'^[a-zA-Z0-9\s\-_]+$')
    
    # XSS patterns to block
    XSS_PATTERNS = [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            r'<script',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'eval\(',
            r'document\.cookie',
            r'<iframe',
            r'<embed',
            r'<object',
            r'<applet',
            r'<meta',
            r'<link',
            r'expression\(',
            r'vbscript:',
            r'data:text/html',
        ]
    ]
    
    @classmethod
    def validate_product_id(cls, product_id: str) -> Tuple[bool, str]:
        """Validate product ID."""
        if not product_id or not isinstance(product_id, str):
            return False, "Product ID is required"
        
        product_id = product_id.strip()
        
        if len(product_id) > 50:
            return False, "Product ID too long"
        
        if not re.match(r'^[a-zA-Z0-9\-_]+$', product_id):
            return False, "Product ID contains invalid characters"
        
        return True, product_id
    
    @classmethod
    def validate_name(cls, name: str) -> Tuple[bool, str]:
        """Validate and sanitize product name."""
        if not name or not isinstance(name, str):
            return False, "Product name is required"
        
        name = name.strip()
        
        if len(name) > Config.MAX_NAME_LENGTH:
            return False, f"Name exceeds {Config.MAX_NAME_LENGTH} characters"
        
        if len(name) < 2:
            return False, "Name must be at least 2 characters"
        
        if not cls.NAME_PATTERN.match(name):
            return False, "Name contains invalid characters"
        
        # Check for XSS
        for pattern in cls.XSS_PATTERNS:
            if pattern.search(name):
                return False, "Name contains potentially dangerous content"
        
        return True, name
    
    @classmethod
    def validate_description(cls, description: str) -> Tuple[bool, str]:
        """Validate and sanitize description."""
        if not isinstance(description, str):
            return False, "Invalid description format"
        
        description = description.strip()
        
        if len(description) > Config.MAX_DESCRIPTION_LENGTH:
            return False, f"Description exceeds {Config.MAX_DESCRIPTION_LENGTH} characters"
        
        # Check for XSS
        for pattern in cls.XSS_PATTERNS:
            if pattern.search(description):
                return False, "Description contains potentially dangerous content"
        
        # HTML encode dangerous characters
        description = (description
                      .replace('&', '&amp;')
                      .replace('<', '&lt;')
                      .replace('>', '&gt;')
                      .replace('"', '&quot;')
                      .replace("'", '&#x27;'))
        
        return True, description
    
    @classmethod
    def validate_price(cls, price: Any) -> Tuple[bool, float]:
        """Validate price."""
        try:
            price = float(price)
        except (TypeError, ValueError):
            return False, 0.0
        
        if price < Config.MIN_PRICE:
            return False, 0.0
        
        if price > Config.MAX_PRICE:
            return False, 0.0
        
        # Round to 2 decimal places
        price = round(price, 2)
        
        return True, price
    
    @classmethod
    def validate_stock(cls, stock: Any) -> Tuple[bool, int]:
        """Validate stock quantity."""
        try:
            stock = int(stock)
        except (TypeError, ValueError):
            return False, 0
        
        if stock < 0:
            return False, 0
        
        if stock > Config.MAX_STOCK:
            return False, 0
        
        return True, stock
    
    @classmethod
    def validate_sku(cls, sku: str) -> Tuple[bool, str]:
        """Validate SKU."""
        if not sku or not isinstance(sku, str):
            return False, "SKU is required"
        
        sku = sku.strip().upper()
        
        if len(sku) > 50:
            return False, "SKU too long"
        
        if not cls.SKU_PATTERN.match(sku):
            return False, "SKU contains invalid characters"
        
        return True, sku
    
    @classmethod
    def validate_category(cls, category: str) -> Tuple[bool, str]:
        """Validate category."""
        if not isinstance(category, str):
            return False, ""
        
        category = category.strip()
        
        if len(category) > 100:
            return False, "Category too long"
        
        if category and not cls.CATEGORY_PATTERN.match(category):
            return False, "Category contains invalid characters"
        
        return True, category
    
    @classmethod
    def validate_pagination(cls, page: Any, page_size: Any) -> Tuple[int, int]:
        """Validate pagination parameters."""
        try:
            page = int(page) if page else 1
            page_size = int(page_size) if page_size else Config.DEFAULT_PAGE_SIZE
        except (TypeError, ValueError):
            page, page_size = 1, Config.DEFAULT_PAGE_SIZE
        
        if page < 1:
            page = 1
        
        if page_size < 1:
            page_size = Config.DEFAULT_PAGE_SIZE
        
        if page_size > Config.MAX_PAGE_SIZE:
            page_size = Config.MAX_PAGE_SIZE
        
        return page, page_size

# ============================================================================
# Product Repository
# ============================================================================

class ProductRepository:
    """Secure data access layer for products."""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.validator = ProductValidator()
    
    def create(self, product_data: Dict[str, Any], user_id: str = 'system') -> Tuple[Optional[Product], Optional[str]]:
        """Create a new product."""
        try:
            # Validate required fields
            name_valid, name = self.validator.validate_name(product_data.get('name', ''))
            if not name_valid:
                return None, name
            
            sku_valid, sku = self.validator.validate_sku(product_data.get('sku', ''))
            if not sku_valid:
                return None, sku
            
            price_valid, price = self.validator.validate_price(product_data.get('price', 0))
            if not price_valid:
                return None, "Invalid price"
            
            stock_valid, stock = self.validator.validate_stock(product_data.get('stock', 0))
            if not stock_valid:
                return None, "Invalid stock"
            
            desc_valid, description = self.validator.validate_description(
                product_data.get('description', '')
            )
            if not desc_valid:
                return None, description
            
            cat_valid, category = self.validator.validate_category(
                product_data.get('category', '')
            )
            if not cat_valid:
                return None, category
            
            # Generate product ID
            product_id = f"prod_{uuid.uuid4().hex[:12]}"
            now = datetime.utcnow().isoformat() + 'Z'
            
            with self.db.get_connection() as conn:
                # Check SKU uniqueness
                cursor = conn.execute(
                    "SELECT id FROM products WHERE sku = ? AND is_active = 1",
                    (sku,)
                )
                if cursor.fetchone():
                    return None, f"SKU '{sku}' already exists"
                
                # Insert product
                conn.execute("""
                    INSERT INTO products (
                        id, name, description, price, stock, category, sku,
                        is_active, created_at, updated_at, created_by, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 1)
                """, (
                    product_id, name, description, price, stock, category, sku,
                    now, now, user_id
                ))
                
                logger.info(f"Product created: {product_id} by {user_id}")
                
                return Product(
                    id=product_id,
                    name=name,
                    description=description,
                    price=price,
                    stock=stock,
                    category=category,
                    sku=sku,
                    is_active=True,
                    created_at=now,
                    updated_at=now,
                    created_by=user_id
                ), None
                
        except sqlite3.IntegrityError as e:
            logger.error(f"Integrity error creating product: {str(e)}")
            return None, "Data integrity error"
        except Exception as e:
            logger.error(f"Error creating product: {str(e)}")
            return None, "Internal error creating product"
    
    def get_by_id(self, product_id: str) -> Optional[Product]:
        """Get product by ID."""
        try:
            valid, sanitized_id = self.validator.validate_product_id(product_id)
            if not valid:
                return None
            
            with self.db.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM products WHERE id = ? AND is_active = 1",
                    (sanitized_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    return Product.from_row(row)
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting product {product_id}: {str(e)}")
            return None
    
    def list_products(self, 
                     page: int = 1, 
                     page_size: int = 20,
                     category: Optional[str] = None,
                     search: Optional[str] = None,
                     min_price: Optional[float] = None,
                     max_price: Optional[float] = None,
                     sort_by: str = 'created_at',
                     sort_order: str = 'DESC') -> Tuple[List[Product], int]:
        """List products with filtering, sorting, and pagination."""
        try:
            # Validate pagination
            page, page_size = self.validator.validate_pagination(page, page_size)
            
            # Validate sort parameters
            allowed_sort_columns = {'name', 'price', 'stock', 'created_at', 'updated_at'}
            if sort_by not in allowed_sort_columns:
                sort_by = 'created_at'
            
            sort_order = 'DESC' if sort_order.upper() not in ('ASC', 'DESC') else sort_order.upper()
            
            with self.db.get_connection() as conn:
                # Build query
                conditions = ["is_active = 1"]
                params = []
                
                if category:
                    cat_valid, sanitized_cat = self.validator.validate_category(category)
                    if cat_valid and sanitized_cat:
                        conditions.append("category = ?")
                        params.append(sanitized_cat)
                
                if search:
                    # Validate search term
                    if isinstance(search, str) and len(search) <= 100:
                        # Remove special characters for FTS-like search
                        search_term = re.sub(r'[^\w\s]', '', search).strip()
                        if search_term:
                            conditions.append(
                                "(name LIKE ? OR description LIKE ? OR sku LIKE ?)"
                            )
                            search_pattern = f"%{search_term}%"
                            params.extend([search_pattern, search_pattern, search_pattern])
                
                if min_price is not None:
                    try:
                        min_price = float(min_price)
                        if min_price >= Config.MIN_PRICE:
                            conditions.append("price >= ?")
                            params.append(min_price)
                    except (TypeError, ValueError):
                        pass
                
                if max_price is not None:
                    try:
                        max_price = float(max_price)
                        if max_price <= Config.MAX_PRICE:
                            conditions.append("price <= ?")
                            params.append(max_price)
                    except (TypeError, ValueError):
                        pass
                
                where_clause = " AND ".join(conditions)
                
                # Get total count
                count_query = f"SELECT COUNT(*) FROM products WHERE {where_clause}"
                cursor = conn.execute(count_query, params)
                total_count = cursor.fetchone()[0]
                
                # Get products
                offset = (page - 1) * page_size
                query = f"""
                    SELECT * FROM products 
                    WHERE {where_clause}
                    ORDER BY {sort_by} {sort_order}
                    LIMIT ? OFFSET ?
                """
                cursor = conn.execute(query, params + [page_size, offset])
                rows = cursor.fetchall()
                
                products = [Product.from_row(row) for row in rows]
                
                return products, total_count
                
        except Exception as e:
            logger.error(f"Error listing products: {str(e)}")
            return [], 0
    
    def update(self, product_id: str, update_data: Dict[str, Any], 
               user_id: str = 'system') -> Tuple[Optional[Product], Optional[str]]:
        """Update a product."""
        try:
            # Validate product ID
            id_valid, sanitized_id = self.validator.validate_product_id(product_id)
            if not id_valid:
                return None, "Invalid product ID"
            
            with self.db.get_connection() as conn:
                # Get existing product
                cursor = conn.execute(
                    "SELECT * FROM products WHERE id = ? AND is_active = 1",
                    (sanitized_id,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return None, "Product not found"
                
                existing = Product.from_row(row)
                
                # Build update fields
                updates = []
                params = []
                
                if 'name' in update_data:
                    valid, name = self.validator.validate_name(update_data['name'])
                    if not valid:
                        return None, name
                    updates.append("name = ?")
                    params.append(name)
                
                if 'description' in update_data:
                    valid, desc = self.validator.validate_description(update_data['description'])
                    if not valid:
                        return None, desc
                    updates.append("description = ?")
                    params.append(desc)
                
                if 'price' in update_data:
                    valid, price = self.validator.validate_price(update_data['price'])
                    if not valid:
                        return None, "Invalid price"
                    updates.append("price = ?")
                    params.append(price)
                
                if 'stock' in update_data:
                    valid, stock = self.validator.validate_stock(update_data['stock'])
                    if not valid:
                        return None, "Invalid stock"
                    updates.append("stock = ?")
                    params.append(stock)
                
                if 'category' in update_data:
                    valid, category = self.validator.validate_category(update_data['category'])
                    if not valid:
                        return None, category
                    updates.append("category = ?")
                    params.append(category)
                
                if 'sku' in update_data:
                    valid, sku = self.validator.validate_sku(update_data['sku'])
                    if not valid:
                        return None, sku
                    
                    # Check SKU uniqueness (excluding current product)
                    cursor = conn.execute(
                        "SELECT id FROM products WHERE sku = ? AND id != ? AND is_active = 1",
                        (sku, sanitized_id)
                    )
                    if cursor.fetchone():
                        return None, f"SKU '{sku}' already exists"
                    
                    updates.append("sku = ?")
                    params.append(sku)
                
                if not updates:
                    return existing, None  # No changes
                
                # Add timestamp and version
                now = datetime.utcnow().isoformat() + 'Z'
                updates.append("updated_at = ?")
                params.append(now)
                updates.append("version = version + 1")
                
                # Add product ID to params
                params.append(sanitized_id)
                
                # Execute update
                query = f"UPDATE products SET {', '.join(updates)} WHERE id = ?"
                conn.execute(query, params)
                
                # Fetch updated product
                cursor = conn.execute(
                    "SELECT * FROM products WHERE id = ?",
                    (sanitized_id,)
                )
                updated_row = cursor.fetchone()
                
                logger.info(f"Product updated: {sanitized_id} by {user_id}")
                
                return Product.from_row(updated_row), None
                
        except Exception as e:
            logger.error(f"Error updating product {product_id}: {str(e)}")
            return None, "Internal error updating product"
    
    def delete(self, product_id: str, user_id: str = 'system') -> Tuple[bool, Optional[str]]:
        """Soft delete a product."""
        try:
            valid, sanitized_id = self.validator.validate_product_id(product_id)
            if not valid:
                return False, "Invalid product ID"
            
            with self.db.get_connection() as conn:
                cursor = conn.execute(
                    "UPDATE products SET is_active = 0, updated_at = ? WHERE id = ? AND is_active = 1",
                    (datetime.utcnow().isoformat() + 'Z', sanitized_id)
                )
                
                if cursor.rowcount == 0:
                    return False, "Product not found"
                
                logger.info(f"Product deleted: {sanitized_id} by {user_id}")
                return True, None
                
        except Exception as e:
            logger.error(f"Error deleting product {product_id}: {str(e)}")
            return False, "Internal error deleting product"

# ============================================================================
# Authentication and Authorization
# ============================================================================

class AuthManager:
    """Authentication and authorization manager."""
    
    # Mock API keys (use database in production)
    API_KEYS = {
        'sk_admin_key_123': {'role': 'admin', 'user_id': 'admin_001'},
        'sk_user_key_456': {'role': 'user', 'user_id': 'user_001'},
        'sk_readonly_key_789': {'role': 'readonly', 'user_id': 'reader_001'}
    }
    
    @classmethod
    def validate_api_key(cls, api_key: str) -> Optional[Dict[str, str]]:
        """Validate API key and return user info."""
        if not api_key:
            return None
        
        # Constant-time comparison to prevent timing attacks
        valid_key = None
        for key in cls.API_KEYS:
            if hmac.compare_digest(api_key, key):
                valid_key = key
                break
        
        if valid_key:
            return cls.API_KEYS[valid_key]
        
        # Add delay for invalid keys to prevent timing attacks
        time.sleep(secrets.SystemRandom().uniform(0.05, 0.1))
        return None
    
    @classmethod
    def check_permission(cls, user_info: Dict[str, str], action: str) -> bool:
        """Check if user has permission for action."""
        if not user_info:
            return False
        
        role = user_info.get('role', '')
        
        permissions = {
            'admin': ['create', 'read', 'update', 'delete'],
            'user': ['create', 'read', 'update'],
            'readonly': ['read']
        }
        
        return action in permissions.get(role, [])

# ============================================================================
# Flask Application
# ============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_BODY_SIZE

# Rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT_DEFAULT]
)

# Initialize repository
product_repo = ProductRepository()

# ============================================================================
# Decorators
# ============================================================================

def require_auth(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get(Config.API_KEY_HEADER)
        
        if not api_key:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'API key is required'
            }), 401
        
        user_info = AuthManager.validate_api_key(api_key)
        if not user_info:
            logger.warning(f"Invalid API key from IP: {request.remote_addr}")
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid API key'
            }), 401
        
        g.user_info = user_info
        return f(*args, **kwargs)
    return decorated_function

def require_permission(action: str):
    """Decorator to check user permissions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user_info'):
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'Authentication required'
                }), 401
            
            if not AuthManager.check_permission(g.user_info, action):
                logger.warning(
                    f"Permission denied for user {g.user_info.get('user_id')} "
                    f"attempting {action}"
                )
                return jsonify({
                    'error': 'Forbidden',
                    'message': 'Insufficient permissions'
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_json(f):
    """Decorator to validate JSON payload."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({
                'error': 'Bad Request',
                'message': 'Content-Type must be application/json'
            }), 400
        
        try:
            data = request.get_json(force=True, silent=True)
            if data is None:
                raise BadRequest("Invalid JSON")
        except Exception as e:
            return jsonify({
                'error': 'Bad Request',
                'message': 'Invalid JSON payload'
            }), 400
        
        g.json_data = data
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# API Endpoints
# ============================================================================

@app.route('/api/v1/products', methods=['POST'])
@require_auth
@require_permission('create')
@validate_json
@limiter.limit(Config.RATE_LIMIT_STRICT)
def create_product():
    """
    Create a new product.
    
    Request body:
    {
        "name": "Product Name",
        "sku": "PROD-001",
        "price": 29.99,
        "stock": 100,
        "description": "Product description",
        "category": "Electronics"
    }
    """
    try:
        data = g.json_data
        user_id = g.user_info.get('user_id', 'system')
        
        product, error = product_repo.create(data, user_id)
        
        if error:
            return jsonify({
                'error': 'Bad Request',
                'message': error
            }), 400
        
        return jsonify({
            'success': True,
            'data': product.to_dict(),
            'message': 'Product created successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Error in create_product: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500

@app.route('/api/v1/products', methods=['GET'])
@require_auth
@require_permission('read')
def list_products():
    """
    List products with filtering and pagination.
    
    Query parameters:
    - page: Page number (default: 1)
    - page_size: Items per page (default: 20, max: 100)
    - category: Filter by category
    - search: Search in name and description
    - min_price: Minimum price filter
    - max_price: Maximum price filter
    - sort_by: Sort field (default: created_at)
    - sort_order: Sort direction (ASC/DESC, default: DESC)
    """
    try:
        # Get query parameters
        page = request.args.get('page', 1)
        page_size = request.args.get('page_size', Config.DEFAULT_PAGE_SIZE)
        category = request.args.get('category')
        search = request.args.get('search')
        min_price = request.args.get('min_price')
        max_price = request.args.get('max_price')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'DESC')
        
        # Get products
        products, total_count = product_repo.list_products(
            page=page,
            page_size=page_size,
            category=category,
            search=search,
            min_price=min_price,
            max_price=max_price,
            sort_by=sort_by,
            sort_order=sort_order
        )
        
        # Calculate pagination metadata
        page, page_size = ProductValidator.validate_pagination(page, page_size)
        total_pages = (total_count + page_size - 1) // page_size
        
        return jsonify({
            'success': True,
            'data': [p.to_dict() for p in products],
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': total_pages,
                'total_items': total_count,
                'has_next': page < total_pages,
                'has_previous': page > 1
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in list_products: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500

@app.route('/api/v1/products/<product_id>', methods=['GET'])
@require_auth
@require_permission('read')
def get_product(product_id: str):
    """Get a single product by ID."""
    try:
        product = product_repo.get_by_id(product_id)
        
        if not product:
            return jsonify({
                'error': 'Not Found',
                'message': 'Product not found'
            }), 404
        
        return jsonify({
            'success': True,
            'data': product.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Error in get_product: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500

@app.route('/api/v1/products/<product_id>', methods=['PUT'])
@require_auth
@require_permission('update')
@validate_json
@limiter.limit(Config.RATE_LIMIT_STRICT)
def update_product(product_id: str):
    """
    Update a product.
    
    Request body can include any of:
    {
        "name": "Updated Name",
        "price": 39.99,
        "stock": 150,
        "description": "Updated description",
        "category": "Updated Category",
        "sku": "PROD-002"
    }
    """
    try:
        data = g.json_data
        user_id = g.user_info.get('user_id', 'system')
        
        product, error = product_repo.update(product_id, data, user_id)
        
        if error:
            status_code = 404 if error == "Product not found" else 400
            return jsonify({
                'error': 'Not Found' if status_code == 404 else 'Bad Request',
                'message': error
            }), status_code
        
        return jsonify({
            'success': True,
            'data': product.to_dict(),
            'message': 'Product updated successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in update_product: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500

@app.route('/api/v1/products/<product_id>', methods=['DELETE'])
@require_auth
@require_permission('delete')
@limiter.limit(Config.RATE_LIMIT_STRICT)
def delete_product(product_id: str):
    """Delete a product (soft delete)."""
    try:
        user_id = g.user_info.get('user_id', 'system')
        
        success, error = product_repo.delete(product_id, user_id)
        
        if not success:
            return jsonify({
                'error': 'Not Found',
                'message': error or 'Product not found'
            }), 404
        
        return jsonify({
            'success': True,
            'message': 'Product deleted successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in delete_product: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500

# Health check endpoint
@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    try:
        # Test database connection
        db = DatabaseManager()
        with db.get_connection() as conn:
            conn.execute("SELECT 1")
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'version': '1.0.0'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({
        'error': 'Bad Request',
        'message': str(error.description) if error.description else 'Invalid request'
    }), 400

@app.errorhandler(401)
def unauthorized_error(error):
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required'
    }), 401

@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({
        'error': 'Forbidden',
        'message': 'You don\'t have permission to access this resource'
    }), 403

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested resource was not found'
    }), 404

@app.errorhandler(405)
def method_not_allowed_error(error):
    return jsonify({
        'error': 'Method Not Allowed',
        'message': 'The method is not allowed for this endpoint'
    }), 405

@app.errorhandler(429)
def too_many_requests_error(error):
    return jsonify({
        'error': 'Too Many Requests',
        'message': 'Rate limit exceeded',
        'retry_after': error.description if error.description else 60
    }), 429

@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred'
    }), 500

# ============================================================================
# Security Headers
# ============================================================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# ============================================================================
# Application Entry Point
# ============================================================================

if __name__ == '__main__':
    # In production, use Gunicorn with HTTPS:
    # gunicorn -w 4 -b 0.0.0.0:8000 --certfile=cert.pem --keyfile=key.pem app:app
    app.run(
        debug=False,
        host='0.0.0.0',
        port=8000,
        ssl_context='adhoc'  # Use proper certificates in production
    )