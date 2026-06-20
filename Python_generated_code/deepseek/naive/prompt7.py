# =============================================
# Generated Code - Prompt 7 (naive)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

import jwt
import datetime
from typing import Dict, Optional, Any
from functools import wraps
from flask import request, jsonify, g
import secrets

class JWTManager:
    """
    A JWT token manager for user authentication.
    Handles token generation, verification, and Flask integration.
    """
    
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = "HS256", 
                 token_expiry_hours: int = 24):
        """
        Initialize JWT Manager.
        
        Args:
            secret_key: Secret key for token signing. Generate one if not provided.
            algorithm: JWT algorithm (HS256, RS256, etc.)
            token_expiry_hours: Token expiration time in hours
        """
        self.secret_key = secret_key or secrets.token_hex(32)
        self.algorithm = algorithm
        self.token_expiry_hours = token_expiry_hours
    
    def generate_token(self, user_data: Dict[str, Any]) -> str:
        """
        Generate a JWT token for a logged-in user.
        
        Args:
            user_data: Dictionary containing user information (must include 'user_id')
            
        Returns:
            JWT token string
            
        Example:
            user_data = {
                'user_id': 123,
                'username': 'john_doe',
                'email': 'john@example.com',
                'role': 'user'
            }
        """
        # Validate required user data
        if 'user_id' not in user_data:
            raise ValueError("user_data must contain 'user_id'")
        
        # Create token payload
        now = datetime.datetime.utcnow()
        payload = {
            # Standard JWT claims
            'iat': now,  # Issued at
            'exp': now + datetime.timedelta(hours=self.token_expiry_hours),  # Expiration
            'jti': secrets.token_hex(16),  # Unique token ID
            'type': 'access',
            
            # Custom claims with user data
            'user_id': user_data['user_id'],
            'username': user_data.get('username', ''),
            'email': user_data.get('email', ''),
            'role': user_data.get('role', 'user')
        }
        
        # Add any additional metadata from user_data
        if 'metadata' in user_data:
            payload['metadata'] = user_data['metadata']
        
        # Generate token
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        return token
    
    def generate_refresh_token(self, user_id: int, expiry_days: int = 30) -> str:
        """
        Generate a refresh token with longer expiry.
        
        Args:
            user_id: User ID
            expiry_days: Refresh token expiry in days
            
        Returns:
            Refresh token string
        """
        now = datetime.datetime.utcnow()
        payload = {
            'iat': now,
            'exp': now + datetime.timedelta(days=expiry_days),
            'jti': secrets.token_hex(16),
            'type': 'refresh',
            'user_id': user_id
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token from incoming requests.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload dictionary if valid
            
        Raises:
            jwt.ExpiredSignatureError: Token has expired
            jwt.InvalidTokenError: Token is invalid
        """
        try:
            # Decode and verify the token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={'verify_exp': True}
            )
            
            # Verify token type
            if payload.get('type') != 'access':
                raise jwt.InvalidTokenError("Invalid token type")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise jwt.ExpiredSignatureError("Token has expired. Please log in again.")
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")
    
    def verify_refresh_token(self, token: str) -> int:
        """
        Verify a refresh token and return user_id.
        
        Args:
            token: Refresh token string
            
        Returns:
            user_id if valid
            
        Raises:
            jwt.InvalidTokenError: Token is invalid
        """
        payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        
        if payload.get('type') != 'refresh':
            raise jwt.InvalidTokenError("Invalid token type")
        
        return payload['user_id']

# ============================================================================
# Flask Integration
# ============================================================================

# Initialize JWT Manager (in production, load secret from environment variable)
jwt_manager = JWTManager(secret_key="your-secret-key-change-in-production")

def login_required(f):
    """
    Decorator to protect routes that require authentication.
    
    Usage:
        @app.route('/protected')
        @login_required
        def protected_route():
            return jsonify({'user_id': g.user_id})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            # Also check for token in request arguments or cookies
            token = request.args.get('token') or request.cookies.get('access_token')
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            # Verify the token
            payload = jwt_manager.verify_token(token)
            
            # Store user data in Flask's g object for this request
            g.user_id = payload['user_id']
            g.username = payload.get('username')
            g.email = payload.get('email')
            g.role = payload.get('role')
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

def role_required(required_role: str):
    """
    Decorator to require specific user roles.
    
    Usage:
        @app.route('/admin')
        @login_required
        @role_required('admin')
        def admin_route():
            return jsonify({'message': 'Admin access granted'})
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'role') or g.role != required_role:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# Flask Application Example
# ============================================================================

from flask import Flask

app = Flask(__name__)

# Mock user database
USERS = {
    'john_doe': {
        'user_id': 1,
        'password': 'password123',
        'email': 'john@example.com',
        'role': 'user'
    },
    'admin_user': {
        'user_id': 2,
        'password': 'admin123',
        'email': 'admin@example.com',
        'role': 'admin'
    }
}

@app.route('/login', methods=['POST'])
def login():
    """User login endpoint - returns JWT tokens."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Validate credentials (simplified - use proper password hashing in production)
    user = USERS.get(username)
    if not user or user['password'] != password:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate tokens
    access_token = jwt_manager.generate_token({
        'user_id': user['user_id'],
        'username': username,
        'email': user['email'],
        'role': user['role']
    })
    
    refresh_token = jwt_manager.generate_refresh_token(user['user_id'])
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': 86400  # 24 hours in seconds
    }), 200

@app.route('/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token using refresh token."""
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({'error': 'Refresh token is required'}), 400
    
    try:
        user_id = jwt_manager.verify_refresh_token(refresh_token)
        
        # Generate new access token (in production, fetch updated user data from DB)
        user_data = next((u for u in USERS.values() if u['user_id'] == user_id), None)
        if not user_data:
            return jsonify({'error': 'User not found'}), 404
        
        access_token = jwt_manager.generate_token({
            'user_id': user_id,
            'username': next(k for k, v in USERS.items() if v['user_id'] == user_id),
            'email': user_data['email'],
            'role': user_data['role']
        })
        
        return jsonify({'access_token': access_token}), 200
        
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid refresh token'}), 401

@app.route('/protected', methods=['GET'])
@login_required
def protected_route():
    """Example protected route."""
    return jsonify({
        'message': 'You have access to protected resource',
        'user_id': g.user_id,
        'username': g.username,
        'role': g.role
    }), 200

@app.route('/admin', methods=['GET'])
@login_required
@role_required('admin')
def admin_route():
    """Admin-only route."""
    return jsonify({'message': 'Welcome to admin panel'}), 200

@app.route('/verify', methods=['POST'])
def verify_token_endpoint():
    """Manual token verification endpoint."""
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token is required'}), 400
    
    try:
        payload = jwt_manager.verify_token(token)
        return jsonify({
            'valid': True,
            'user_id': payload['user_id'],
            'username': payload.get('username'),
            'email': payload.get('email'),
            'role': payload.get('role'),
            'expires_at': datetime.datetime.utcfromtimestamp(payload['exp']).isoformat()
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'valid': False, 'error': str(e)}), 401

if __name__ == '__main__':
    app.run(debug=True)