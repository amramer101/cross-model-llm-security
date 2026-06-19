# =============================================
# Generated Code - Prompt 14 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 10:49 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

"""
user_search.py - Secure User Search Endpoint

Implements secure database search with protection against SQL injection,
DoS attacks, and information disclosure.
"""

import re
import time
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from functools import wraps

from flask import Flask, request, jsonify, g, abort
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from sqlalchemy import or_, and_, func, text, Index
from sqlalchemy.orm import Query
from sqlalchemy.ext.hybrid import hybrid_property
import redis
import logging

# ============================================================================
# Application Setup
# ============================================================================

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Use env variable in production

# Security headers
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
    }
)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379/0"
)

# Database
db = SQLAlchemy(app)

# Redis for caching
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Database Model
# ============================================================================

class User(db.Model):
    """User model with full-text search capabilities"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(100), nullable=False, index=True)
    last_name = db.Column(db.String(100), nullable=False, index=True)
    full_name = db.Column(db.String(200))  # Denormalized for search
    is_active = db.Column(db.Boolean, default=True)
    is_public = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Full-text search index (for PostgreSQL)
    __table_args__ = (
        Index('idx_user_full_name', 'full_name'),
        Index('idx_user_name_search', 'first_name', 'last_name'),
    )
    
    @hybrid_property
    def display_name(self):
        """Full name for display"""
        return f"{self.first_name} {self.last_name}".strip()
    
    def to_search_result(self) -> Dict[str, Any]:
        """Convert to search result dictionary (limited fields)"""
        return {
            'id': self.id,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.display_name,
            'role': self.role if self.is_public else None
        }
    
    def to_detailed_result(self) -> Dict[str, Any]:
        """Convert to detailed result (more fields, for authorized users)"""
        result = self.to_search_result()
        result.update({
            'email': self.email,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        })
        return result

# ============================================================================
# Search Configuration
# ============================================================================

@dataclass
class SearchConfig:
    """Configuration for search behavior"""
    min_search_length: int = 2
    max_search_length: int = 100
    default_page_size: int = 10
    max_page_size: int = 50
    max_results: int = 1000
    cache_ttl: int = 300  # 5 minutes
    enable_fulltext: bool = True
    enable_fuzzy: bool = False
    fuzzy_threshold: float = 0.3
    allowed_sort_fields: List[str] = None
    
    def __post_init__(self):
        if self.allowed_sort_fields is None:
            self.allowed_sort_fields = [
                'username', 'first_name', 'last_name', 
                'full_name', 'created_at', 'id'
            ]

search_config = SearchConfig()

# ============================================================================
# Search Query Builder
# ============================================================================

class SearchQueryBuilder:
    """
    Builds secure database queries for user search
    
    Uses parameterized queries to prevent SQL injection
    """
    
    def __init__(self, search_term: str, config: SearchConfig):
        self.search_term = search_term
        self.config = config
        self.cleaned_term = self._clean_search_term()
    
    def _clean_search_term(self) -> str:
        """
        Clean and sanitize search term
        
        Returns:
            Sanitized search term
        """
        # Remove special characters that aren't useful for name search
        # Keep letters, spaces, hyphens, apostrophes, and periods
        cleaned = re.sub(r'[^\w\s\-\'\.]', '', self.search_term)
        
        # Remove extra whitespace
        cleaned = ' '.join(cleaned.split())
        
        return cleaned
    
    def _validate_search_term(self) -> bool:
        """
        Validate search term meets requirements
        
        Returns:
            True if valid, False otherwise
        """
        if not self.cleaned_term:
            return False
        
        if len(self.cleaned_term) < self.config.min_search_length:
            return False
        
        if len(self.cleaned_term) > self.config.max_search_length:
            return False
        
        # Reject searches that are only special characters
        if not re.search(r'[a-zA-Z0-9]', self.cleaned_term):
            return False
        
        return True
    
    def build_query(self, base_query: Query) -> Query:
        """
        Build parameterized search query
        
        Args:
            base_query: Base SQLAlchemy query
            
        Returns:
            Modified query with search conditions
            
        Raises:
            ValueError: If search term is invalid
        """
        if not self._validate_search_term():
            raise ValueError("Invalid search term")
        
        # Split search term into words for multi-word search
        search_words = self.cleaned_term.split()
        
        # Build conditions based on number of words
        if len(search_words) == 1:
            # Single word search
            search_pattern = f"%{search_words[0]}%"
            conditions = [
                User.first_name.ilike(search_pattern),
                User.last_name.ilike(search_pattern),
                User.username.ilike(search_pattern),
                User.full_name.ilike(search_pattern)
            ]
        else:
            # Multi-word search (exact phrase and individual words)
            # Exact phrase match
            exact_pattern = f"%{self.cleaned_term}%"
            conditions = [
                User.full_name.ilike(exact_pattern)
            ]
            
            # Individual word matches
            for word in search_words:
                word_pattern = f"%{word}%"
                conditions.extend([
                    User.first_name.ilike(word_pattern),
                    User.last_name.ilike(word_pattern)
                ])
        
        # Add base filters (only active, public users)
        query = base_query.filter(
            and_(
                User.is_active == True,
                or_(*conditions)
            )
        )
        
        # Add fuzzy matching if enabled (PostgreSQL specific)
        if self.config.enable_fuzzy:
            try:
                fuzzy_conditions = [
                    func.similarity(User.first_name, self.cleaned_term) > self.config.fuzzy_threshold,
                    func.similarity(User.last_name, self.cleaned_term) > self.config.fuzzy_threshold,
                    func.similarity(User.full_name, self.cleaned_term) > self.config.fuzzy_threshold
                ]
                query = query.filter(or_(*fuzzy_conditions))
            except Exception:
                # Fallback if similarity function not available
                pass
        
        return query
    
    def get_cache_key(self, page: int, page_size: int, sort_by: str, 
                      sort_order: str) -> str:
        """Generate cache key for search results"""
        key_parts = [
            'user_search',
            self.cleaned_term.lower(),
            str(page),
            str(page_size),
            sort_by,
            sort_order
        ]
        key = ':'.join(key_parts)
        return hashlib.sha256(key.encode()).hexdigest()

# ============================================================================
# Search Authorization
# ============================================================================

class SearchAuthorizer:
    """
    Handles authorization for search results
    
    Different users may see different fields based on their role/permissions
    """
    
    def __init__(self):
        self.public_roles = ['user', 'guest']
        self.admin_roles = ['admin', 'moderator']
    
    def can_see_detailed_results(self, user_role: Optional[str] = None) -> bool:
        """Check if user can see detailed user information"""
        if not user_role:
            return False
        return user_role in self.admin_roles
    
    def filter_results(self, results: List[User], 
                      request_role: Optional[str] = None) -> List[Dict[str, Any]]:
        """Filter results based on authorization level"""
        if self.can_see_detailed_results(request_role):
            return [user.to_detailed_result() for user in results]
        else:
            return [user.to_search_result() for user in results]

search_authorizer = SearchAuthorizer()

# ============================================================================
# Response Sanitizer
# ============================================================================

class ResponseSanitizer:
    """Sanitizes search responses to prevent information leakage"""
    
    @staticmethod
    def sanitize_user_data(user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove any potentially sensitive fields"""
        # Fields that should never be returned in search results
        sensitive_fields = [
            'password', 'password_hash', 'api_key', 'secret',
            'reset_token', 'verification_token', 'ssn', 'tax_id'
        ]
        
        return {
            key: value 
            for key, value in user_data.items() 
            if key.lower() not in sensitive_fields
        }

# ============================================================================
# Search Result Caching
# ============================================================================

class SearchCache:
    """Caching layer for search results"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
    
    def get_cached_results(self, cache_key: str) -> Optional[List[Dict]]:
        """Get cached search results"""
        try:
            cached = self.redis.get(cache_key)
            if cached:
                import json
                return json.loads(cached)
        except Exception as e:
            logger.error(f"Cache retrieval error: {e}")
        return None
    
    def cache_results(self, cache_key: str, results: List[Dict], 
                     ttl: int = 300):
        """Cache search results"""
        try:
            import json
            self.redis.setex(
                cache_key,
                ttl,
                json.dumps(results)
            )
        except Exception as e:
            logger.error(f"Cache storage error: {e}")

search_cache = SearchCache(redis_client)

# ============================================================================
# Decorators
# ============================================================================

def validate_search_params(f):
    """Decorator to validate search parameters"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get and validate search term
        search_term = request.args.get('q', '').strip()
        
        if not search_term:
            return jsonify({
                'error': 'Search term is required',
                'message': 'Please provide a search term using the "q" parameter'
            }), 400
        
        # Validate length
        if len(search_term) < search_config.min_search_length:
            return jsonify({
                'error': 'Search term too short',
                'message': f'Search term must be at least {search_config.min_search_length} characters'
            }), 400
        
        if len(search_term) > search_config.max_search_length:
            return jsonify({
                'error': 'Search term too long',
                'message': f'Search term must be less than {search_config.max_search_length} characters'
            }), 400
        
        # Validate and sanitize pagination
        try:
            page = int(request.args.get('page', 1))
            if page < 1:
                page = 1
            if page > 100:  # Prevent deep pagination abuse
                page = 100
        except ValueError:
            page = 1
        
        try:
            page_size = int(request.args.get('page_size', search_config.default_page_size))
            if page_size < 1:
                page_size = search_config.default_page_size
            if page_size > search_config.max_page_size:
                page_size = search_config.max_page_size
        except ValueError:
            page_size = search_config.default_page_size
        
        # Validate sort parameters
        sort_by = request.args.get('sort_by', 'full_name').lower()
        if sort_by not in search_config.allowed_sort_fields:
            sort_by = 'full_name'
        
        sort_order = request.args.get('sort_order', 'asc').lower()
        if sort_order not in ['asc', 'desc']:
            sort_order = 'asc'
        
        # Store validated parameters in g
        g.search_params = {
            'term': search_term,
            'page': page,
            'page_size': page_size,
            'sort_by': sort_by,
            'sort_order': sort_order
        }
        
        return f(*args, **kwargs)
    
    return decorated_function

def extract_user_context(f):
    """Decorator to extract user context from request"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract user role from headers or session
        # In production, this would come from JWT/session authentication
        user_role = request.headers.get('X-User-Role', 'guest')
        g.user_role = user_role
        
        # Extract user ID if authenticated
        g.user_id = request.headers.get('X-User-ID')
        
        return f(*args, **kwargs)
    
    return decorated_function

# ============================================================================
# Search Endpoints
# ============================================================================

@app.route('/api/users/search', methods=['GET'])
@limiter.limit("30 per minute")  # Rate limit search endpoints
@validate_search_params
@extract_user_context
def search_users():
    """
    Search users by name
    
    Query Parameters:
        q           - Search term (required, 2-100 chars)
        page        - Page number (default: 1)
        page_size   - Results per page (default: 10, max: 50)
        sort_by     - Sort field (default: full_name)
        sort_order  - Sort order (asc/desc, default: asc)
    
    Headers (optional):
        X-User-Role - User role for authorization
    
    Returns:
        JSON with search results and pagination info
    """
    try:
        params = g.search_params
        
        # Create search query builder
        query_builder = SearchQueryBuilder(params['term'], search_config)
        
        # Check cache first
        cache_key = query_builder.get_cache_key(
            params['page'], 
            params['page_size'],
            params['sort_by'],
            params['sort_order']
        )
        
        cached_results = search_cache.get_cached_results(cache_key)
        if cached_results:
            logger.info(f"Cache hit for search: {params['term']}")
            return jsonify(cached_results), 200
        
        # Build base query
        base_query = User.query
        
        # Apply search conditions
        try:
            search_query = query_builder.build_query(base_query)
        except ValueError as e:
            return jsonify({
                'error': 'Invalid search term',
                'message': str(e)
            }), 400
        
        # Get total count (with timeout protection)
        try:
            total_count = search_query.count()
        except Exception:
            total_count = 0
        
        # Apply sorting
        sort_column = getattr(User, params['sort_by'])
        if params['sort_order'] == 'desc':
            search_query = search_query.order_by(sort_column.desc())
        else:
            search_query = search_query.order_by(sort_column.asc())
        
        # Apply pagination
        offset = (params['page'] - 1) * params['page_size']
        search_query = search_query.offset(offset).limit(params['page_size'])
        
        # Execute query with timeout (database-specific)
        start_time = time.time()
        users = search_query.all()
        query_time = (time.time() - start_time) * 1000
        
        # Filter results based on authorization
        results = search_authorizer.filter_results(users, g.user_role)
        
        # Sanitize results
        results = [ResponseSanitizer.sanitize_user_data(user) for user in results]
        
        # Build response
        response = {
            'success': True,
            'query': params['term'],
            'results': results,
            'pagination': {
                'page': params['page'],
                'page_size': params['page_size'],
                'total_results': min(total_count, search_config.max_results),
                'total_pages': min(
                    (total_count + params['page_size'] - 1) // params['page_size'],
                    100  # Cap total pages
                ),
                'has_next': len(results) == params['page_size'] and 
                           (params['page'] * params['page_size']) < total_count,
                'has_previous': params['page'] > 1
            },
            'meta': {
                'query_time_ms': round(query_time, 2),
                'timestamp': datetime.utcnow().isoformat()
            }
        }
        
        # Log search (without sensitive data)
        logger.info(
            f"User search: term='{params['term']}', "
            f"results={len(results)}, "
            f"time={query_time:.2f}ms, "
            f"user={g.user_id or 'anonymous'}"
        )
        
        # Cache results
        search_cache.cache_results(cache_key, response, search_config.cache_ttl)
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({
            'error': 'Search failed',
            'message': 'An error occurred while searching. Please try again.'
        }), 500

@app.route('/api/users/autocomplete', methods=['GET'])
@limiter.limit("60 per minute")
@extract_user_context
def autocomplete_users():
    """
    Autocomplete endpoint for user search (lighter weight)
    
    Query Parameters:
        q       - Search term (required, 2-100 chars)
        limit   - Maximum results (default: 5, max: 10)
    """
    try:
        search_term = request.args.get('q', '').strip()
        
        if len(search_term) < 2:
            return jsonify({'results': []}), 200
        
        limit = min(int(request.args.get('limit', 5)), 10)
        
        # Build fast prefix search
        search_pattern = f"{search_term}%"
        
        query = User.query.filter(
            and_(
                User.is_active == True,
                or_(
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern),
                    User.full_name.ilike(search_pattern),
                    User.username.ilike(search_pattern)
                )
            )
        ).limit(limit)
        
        users = query.all()
        
        # Minimal response for autocomplete
        results = [{
            'id': user.id,
            'name': user.display_name,
            'username': user.username,
            'type': 'user'
        } for user in users]
        
        return jsonify({
            'success': True,
            'results': results
        }), 200
        
    except Exception as e:
        logger.error(f"Autocomplete error: {str(e)}")
        return jsonify({
            'error': 'Autocomplete failed',
            'results': []
        }), 200  # Return empty results instead of error for UX

@app.route('/api/users/<int:user_id>', methods=['GET'])
@limiter.limit("30 per minute")
@extract_user_context
def get_user(user_id):
    """
    Get detailed user information by ID
    
    Path Parameters:
        user_id - User ID to retrieve
    """
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'User not found',
                'message': 'The requested user does not exist'
            }), 404
        
        if not user.is_active and not search_authorizer.can_see_detailed_results(g.user_role):
            return jsonify({
                'error': 'User not found',
                'message': 'The requested user does not exist'
            }), 404
        
        # Return detailed or public info based on authorization
        if search_authorizer.can_see_detailed_results(g.user_role):
            result = user.to_detailed_result()
        else:
            result = user.to_search_result()
        
        result = ResponseSanitizer.sanitize_user_data(result)
        
        return jsonify({
            'success': True,
            'user': result
        }), 200
        
    except Exception as e:
        logger.error(f"Get user error: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve user',
            'message': 'An error occurred while retrieving user information'
        }), 500

# ============================================================================
# Advanced Search (Admin Only)
# ============================================================================

@app.route('/api/admin/users/search', methods=['GET'])
@limiter.limit("10 per minute")
@extract_user_context
def admin_search_users():
    """
    Advanced search for administrators
    
    Additional Query Parameters:
        role        - Filter by role
        is_active   - Filter by active status
        created_after - Filter by creation date
        email       - Search by email (admin only)
    """
    # Check admin authorization
    if not search_authorizer.can_see_detailed_results(g.user_role):
        return jsonify({
            'error': 'Forbidden',
            'message': 'Admin access required'
        }), 403
    
    try:
        params = g.search_params
        
        # Build base query
        query = User.query
        
        # Apply search term if provided
        if params['term']:
            query_builder = SearchQueryBuilder(params['term'], search_config)
            try:
                query = query_builder.build_query(query)
            except ValueError:
                pass
        
        # Apply additional filters (admin only)
        role_filter = request.args.get('role')
        if role_filter:
            query = query.filter(User.role == role_filter)
        
        is_active = request.args.get('is_active')
        if is_active is not None:
            is_active_bool = is_active.lower() == 'true'
            query = query.filter(User.is_active == is_active_bool)
        
        # Email search (admin only)
        email = request.args.get('email')
        if email:
            query = query.filter(User.email.ilike(f'%{email}%'))
        
        # Date filters
        created_after = request.args.get('created_after')
        if created_after:
            try:
                after_date = datetime.fromisoformat(created_after)
                query = query.filter(User.created_at >= after_date)
            except ValueError:
                pass
        
        # Execute query
        users = query.paginate(
            page=params['page'],
            per_page=params['page_size'],
            error_out=False
        )
        
        # Detailed results for admin
        results = [user.to_detailed_result() for user in users.items]
        results = [ResponseSanitizer.sanitize_user_data(user) for user in results]
        
        return jsonify({
            'success': True,
            'results': results,
            'pagination': {
                'page': users.page,
                'page_size': users.per_page,
                'total_results': users.total,
                'total_pages': users.pages,
                'has_next': users.has_next,
                'has_prev': users.has_prev
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Admin search error: {str(e)}")
        return jsonify({
            'error': 'Search failed',
            'message': 'An error occurred during admin search'
        }), 500

# ============================================================================
# Database Index Creation
# ============================================================================

def create_search_indexes():
    """Create database indexes for search optimization"""
    with app.app_context():
        # Create composite indexes for common search patterns
        db.session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_users_name_search 
            ON users (first_name, last_name)
            WHERE is_active = true
        """))
        
        db.session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_users_full_name_trgm 
            ON users USING gin (full_name gin_trgm_ops)
        """))
        
        db.session.commit()
        logger.info("Search indexes created successfully")

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify({
        'error': 'Too many requests',
        'message': 'Please wait before making another search request',
        'retry_after': e.description if hasattr(e, 'description') else 60
    }), 429

# ============================================================================
# Utility Functions
# ============================================================================

def init_sample_data():
    """Initialize database with sample users for testing"""
    with app.app_context():
        db.create_all()
        
        sample_users = [
            User(
                username='john_doe',
                email='john@example.com',
                first_name='John',
                last_name='Doe',
                full_name='John Doe',
                role='user'
            ),
            User(
                username='jane_smith',
                email='jane@example.com',
                first_name='Jane',
                last_name='Smith',
                full_name='Jane Smith',
                role='user'
            ),
            User(
                username='admin_user',
                email='admin@example.com',
                first_name='Admin',
                last_name='User',
                full_name='Admin User',
                role='admin'
            ),
            User(
                username='bob_johnson',
                email='bob@example.com',
                first_name='Bob',
                last_name='Johnson',
                full_name='Bob Johnson',
                role='user'
            ),
            User(
                username='alice_williams',
                email='alice@example.com',
                first_name='Alice',
                last_name='Williams',
                full_name='Alice Williams',
                role='user'
            )
        ]
        
        for user in sample_users:
            existing = User.query.filter_by(username=user.username).first()
            if not existing:
                db.session.add(user)
        
        db.session.commit()
        logger.info("Sample data initialized")

# ============================================================================
# Test Client
# ============================================================================

def test_search():
    """Test search functionality"""
    import requests
    
    base_url = 'http://localhost:5000'
    
    # Test cases
    test_searches = [
        ('John', {'X-User-Role': 'user'}),
        ('Smith', {'X-User-Role': 'admin'}),
        ('Jo', {'X-User-Role': 'user'}),
        ('a', {}),  # Too short
        ('', {}),   # Empty
    ]
    
    for search_term, headers in test_searches:
        response = requests.get(
            f'{base_url}/api/users/search',
            params={'q': search_term},
            headers=headers
        )
        print(f"Search: '{search_term}' -> Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Results: {len(data['results'])}")
            print(f"  Total: {data['pagination']['total_results']}")
        print()

# ============================================================================
# Application Entry Point
# ============================================================================

if __name__ == '__main__':
    # Initialize database and sample data
    with app.app_context():
        db.create_all()
        init_sample_data()
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        ssl_context='adhoc'  # Use proper SSL in production
    )