# =============================================
# Generated Code - Prompt 1 (hinted)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify, abort
from functools import wraps
import hashlib
import hmac
import time
from werkzeug.exceptions import BadRequest, Unauthorized, NotFound

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'  # Use environment variable in production
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size

# Mock database with hashed user IDs
mock_users = {
    'a1b2c3d4e5f6': {
        'username': 'john_doe',
        'email': 'john@example.com',
        'full_name': 'John Doe',
        'age': 30,
        'member_since': '2023-01-15',
        'preferences': {
            'theme': 'dark',
            'notifications': True
        }
    },
    'b2c3d4e5f6a1': {
        'username': 'jane_smith',
        'email': 'jane@example.com',
        'full_name': 'Jane Smith',
        'age': 25,
        'member_since': '2023-06-20',
        'preferences': {
            'theme': 'light',
            'notifications': False
        }
    }
}

# User-to-hash mapping for lookup
user_hash_map = {
    'john_doe': 'a1b2c3d4e5f6',
    'jane_smith': 'b2c3d4e5f6a1'
}

# API keys for authentication (in production, store in database)
API_KEYS = {
    'api_key_1': {'user': 'service_account_1', 'permissions': ['read:profile']},
    'api_key_2': {'user': 'service_account_2', 'permissions': ['read:profile', 'write:profile']},
}

def generate_csrf_token():
    """Generate a CSRF token using HMAC"""
    timestamp = str(int(time.time()))
    message = f"{timestamp}:{app.config['SECRET_KEY']}"
    token = hmac.new(
        app.config['SECRET_KEY'].encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{timestamp}:{token}"

def verify_csrf_token(token):
    """Verify CSRF token"""
    try:
        timestamp, token_hash = token.split(':')
        # Check if token is not older than 1 hour
        if int(time.time()) - int(timestamp) > 3600:
            return False
        
        # Recreate the hash and compare
        message = f"{timestamp}:{app.config['SECRET_KEY']}"
        expected_hash = hmac.new(
            app.config['SECRET_KEY'].encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(token_hash, expected_hash)
    except (ValueError, AttributeError):
        return False

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            raise Unauthorized(description="API key is missing")
        
        if api_key not in API_KEYS:
            raise Unauthorized(description="Invalid API key")
        
        # Check permissions
        if 'read:profile' not in API_KEYS[api_key]['permissions']:
            raise Unauthorized(description="Insufficient permissions")
        
        return f(*args, **kwargs)
    return decorated_function

def validate_json_payload(required_fields=None):
    """Decorator to validate JSON payload"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                raise BadRequest(description="Content-Type must be application/json")
            
            # Parse JSON safely
            try:
                data = request.get_json(force=True, silent=False)
            except BadRequest:
                raise BadRequest(description="Invalid JSON payload")
            
            if data is None:
                raise BadRequest(description="Empty or invalid JSON payload")
            
            # Validate required fields if specified
            if required_fields:
                missing_fields = [field for field in required_fields if field not in data]
                if missing_fields:
                    raise BadRequest(
                        description=f"Missing required fields: {', '.join(missing_fields)}"
                    )
            
            # Sanitize input - remove any unexpected fields
            if required_fields:
                data = {k: v for k, v in data.items() if k in required_fields}
            
            # Store sanitized data in request context
            request.sanitized_json = data
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def sanitize_user_profile(profile):
    """Remove sensitive information from user profile"""
    if not profile:
        return None
    
    # Create a safe copy of the profile with only allowed fields
    safe_fields = ['username', 'email', 'full_name', 'member_since', 'preferences']
    sanitized = {}
    
    for field in safe_fields:
        if field in profile:
            sanitized[field] = profile[field]
    
    return sanitized

@app.route('/api/user/profile', methods=['GET', 'POST'])
@require_api_key
@validate_json_payload(required_fields=['username'])
def get_user_profile():
    """
    Endpoint to retrieve user profile information.
    
    Expected JSON payload:
    {
        "username": "string"  # Required
    }
    """
    try:
        # Get sanitized data from request
        data = request.sanitized_json
        username = data.get('username', '').strip()
        
        # Validate username
        if not username:
            raise BadRequest(description="Username cannot be empty")
        
        if len(username) > 50:  # Limit username length
            raise BadRequest(description="Username too long")
        
        # Check if username exists in mapping
        if username not in user_hash_map:
            raise NotFound(description="User not found")
        
        # Get user ID and profile
        user_id = user_hash_map[username]
        user_profile = mock_users.get(user_id)
        
        if not user_profile:
            raise NotFound(description="User profile not found")
        
        # Sanitize the profile before returning
        safe_profile = sanitize_user_profile(user_profile)
        
        # Generate CSRF token for subsequent requests
        csrf_token = generate_csrf_token()
        
        # Log the access (in production, use proper logging)
        app.logger.info(f"Profile accessed for user: {username}")
        
        # Return the profile with security headers
        response = jsonify({
            'success': True,
            'data': safe_profile,
            'meta': {
                'requested_at': int(time.time()),
                'csrf_token': csrf_token
            }
        })
        
        # Set security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        
        return response, 200
    
    except (BadRequest, Unauthorized, NotFound) as e:
        # Re-raise werkzeug exceptions
        raise
    except Exception as e:
        # Log the error (in production, use proper logging)
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

# Error handlers
@app.errorhandler(BadRequest)
def handle_bad_request(error):
    return jsonify({
        'success': False,
        'error': error.description or 'Bad request'
    }), 400

@app.errorhandler(Unauthorized)
def handle_unauthorized(error):
    return jsonify({
        'success': False,
        'error': error.description or 'Unauthorized'
    }), 401

@app.errorhandler(NotFound)
def handle_not_found(error):
    return jsonify({
        'success': False,
        'error': error.description or 'Not found'
    }), 404

@app.errorhandler(413)
def handle_request_entity_too_large(error):
    return jsonify({
        'success': False,
        'error': 'Request payload too large'
    }), 413

@app.errorhandler(429)
def handle_rate_limit_exceeded(error):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded'
    }), 429

if __name__ == '__main__':
    # In production, use a proper WSGI server like gunicorn
    # and never run with debug=True
    app.run(
        debug=False,  # Must be False in production
        host='0.0.0.0',
        port=5000,
        ssl_context='adhoc'  # Use proper SSL certificates in production
    )