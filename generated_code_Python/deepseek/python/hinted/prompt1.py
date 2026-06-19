# =============================================
# Generated Code - Prompt 1 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError
from functools import wraps
import logging
from typing import Dict, Optional, Any
import re

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mock database
users_db: Dict[str, Dict[str, Any]] = {
    "user_123": {
        "id": "user_123",
        "username": "john_doe",
        "email": "john@example.com",
        "full_name": "John Doe",
        "age": 30,
        "city": "New York",
        "is_active": True,
        "created_at": "2023-01-15T10:30:00Z"
    },
    "user_456": {
        "id": "user_456",
        "username": "jane_smith",
        "email": "jane@example.com",
        "full_name": "Jane Smith",
        "age": 25,
        "city": "San Francisco",
        "is_active": True,
        "created_at": "2023-02-20T14:15:00Z"
    }
}

# Rate limiting configuration (simple in-memory implementation)
from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock

class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = Lock()
    
    def is_allowed(self, identifier: str) -> bool:
        with self.lock:
            now = datetime.now()
            # Remove old requests
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if now - req_time < timedelta(seconds=self.window_seconds)
            ]
            
            # Check if limit exceeded
            if len(self.requests[identifier]) >= self.max_requests:
                return False
            
            # Record this request
            self.requests[identifier].append(now)
            return True

rate_limiter = RateLimiter(max_requests=10, window_seconds=60)

# Input validation decorator
def validate_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            raise BadRequest("Content-Type must be application/json")
        
        try:
            data = request.get_json(force=True, silent=True)
            if data is None:
                raise BadRequest("Invalid JSON payload")
        except Exception as e:
            logger.error(f"JSON parsing error: {str(e)}")
            raise BadRequest("Invalid JSON payload")
        
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr or 'unknown'
        if not rate_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return jsonify({
                "error": "Too many requests",
                "message": "Please try again later"
            }), 429
        return f(*args, **kwargs)
    return decorated_function

# Input sanitization function
def sanitize_user_id(user_id: str) -> str:
    """Sanitize and validate user ID input."""
    # Remove any whitespace
    user_id = user_id.strip()
    
    # Validate format (alphanumeric with underscores only)
    if not re.match(r'^[a-zA-Z0-9_]+$', user_id):
        raise ValueError("Invalid user ID format")
    
    # Limit length
    if len(user_id) > 50:
        raise ValueError("User ID too long")
    
    return user_id

# Sensitive data filtering
def filter_sensitive_data(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive fields before sending response."""
    safe_data = user_data.copy()
    
    # Fields to exclude from response
    sensitive_fields = ['password', 'ssn', 'credit_card', 'secret_key']
    
    for field in sensitive_fields:
        safe_data.pop(field, None)
    
    return safe_data

# Main endpoint
@app.route('/api/user/profile', methods=['POST'])
@rate_limit
@validate_json
def get_user_profile():
    """
    Get user profile based on user ID from JSON payload.
    
    Expected JSON format:
    {
        "user_id": "user_123"
    }
    """
    try:
        # Get and validate JSON data
        data = request.get_json()
        
        # Validate required fields
        if 'user_id' not in data:
            return jsonify({
                "error": "Bad Request",
                "message": "user_id is required"
            }), 400
        
        # Sanitize and validate user_id
        try:
            user_id = sanitize_user_id(data['user_id'])
        except ValueError as e:
            return jsonify({
                "error": "Bad Request",
                "message": str(e)
            }), 400
        
        # Log request (without sensitive data)
        logger.info(f"User profile request for user_id: {user_id}")
        
        # Query mock database
        user_data = users_db.get(user_id)
        
        if user_data is None:
            logger.warning(f"User not found: {user_id}")
            return jsonify({
                "error": "Not Found",
                "message": "User not found"
            }), 404
        
        # Filter sensitive data and return
        safe_user_data = filter_sensitive_data(user_data)
        
        return jsonify({
            "success": True,
            "data": safe_user_data
        }), 200
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred"
        }), 500

# Error handlers
@app.errorhandler(BadRequest)
def handle_bad_request(error):
    return jsonify({
        "error": "Bad Request",
        "message": str(error.description)
    }), 400

@app.errorhandler(404)
def handle_not_found(error):
    return jsonify({
        "error": "Not Found",
        "message": "The requested resource was not found"
    }), 404

@app.errorhandler(500)
def handle_internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        "error": "Internal Server Error",
        "message": "An unexpected error occurred"
    }), 500

if __name__ == '__main__':
    # In production, use a proper WSGI server like Gunicorn
    # and set debug=False
    app.run(debug=False, host='0.0.0.0', port=5000)