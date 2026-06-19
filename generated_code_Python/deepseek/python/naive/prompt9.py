# =============================================
# Generated Code - Prompt 9 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 11:00 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import jwt
import datetime
from functools import wraps
from flask import request, jsonify, g
from typing import Optional, Dict, Any, Callable

# Configuration - in production, store these in environment variables
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

def generate_jwt_token(user_id: str, username: str, additional_claims: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate a JWT token for a logged-in user.
    
    Args:
        user_id: Unique identifier for the user
        username: Username of the user
        additional_claims: Optional dictionary of additional claims to include in the token
    
    Returns:
        str: Encoded JWT token
    """
    # Set token expiration time
    expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS)
    
    # Create the payload
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': expiry,
        'iat': datetime.datetime.utcnow(),
        'iss': 'your-app-name'  # Issuer claim
    }
    
    # Add additional claims if provided
    if additional_claims:
        payload.update(additional_claims)
    
    # Generate the token
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    return token


def verify_jwt_token(token: str) -> Dict[str, Any]:
    """
    Verify a JWT token and return its decoded payload.
    
    Args:
        token: JWT token string to verify
    
    Returns:
        Dict: Decoded token payload if valid
    
    Raises:
        jwt.ExpiredSignatureError: If token has expired
        jwt.InvalidTokenError: If token is invalid
    """
    try:
        # Decode and verify the token
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={'verify_exp': True}
        )
        return payload
    
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError('Token has expired')
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError(f'Invalid token: {str(e)}')


# Flask decorator for protecting routes
def require_auth(f: Callable) -> Callable:
    """
    Decorator to protect Flask routes with JWT authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Authorization header is missing'}), 401
        
        # Check if it's a Bearer token
        try:
            token_type, token = auth_header.split(' ', 1)
            if token_type.lower() != 'bearer':
                return jsonify({'error': 'Invalid authorization type. Must be Bearer'}), 401
        except ValueError:
            return jsonify({'error': 'Invalid authorization header format'}), 401
        
        try:
            # Verify the token
            payload = verify_jwt_token(token)
            
            # Attach user information to Flask's g object
            g.user_id = payload['user_id']
            g.username = payload['username']
            g.token_payload = payload
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired. Please log in again'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': str(e)}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


# Optional: Refresh token function
def refresh_jwt_token(token: str) -> Optional[str]:
    """
    Refresh an expired or near-expiry JWT token.
    
    Args:
        token: Current JWT token
    
    Returns:
        Optional[str]: New JWT token if refresh successful, None otherwise
    """
    try:
        # Verify without expiry check to get the payload
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={'verify_exp': False}
        )
        
        # Remove expiry-related claims
        payload.pop('exp', None)
        payload.pop('iat', None)
        
        # Generate new token with updated expiry
        new_token = generate_jwt_token(
            user_id=payload['user_id'],
            username=payload['username'],
            additional_claims=payload
        )
        
        return new_token
    
    except jwt.InvalidTokenError:
        return None


# Example usage with Flask
if __name__ == "__main__":
    from flask import Flask
    
    app = Flask(__name__)
    
    @app.route('/login', methods=['POST'])
    def login():
        """
        Example login endpoint that generates a JWT token.
        In production, you'd validate credentials against a database.
        """
        data = request.get_json()
        
        # Mock authentication - replace with real authentication logic
        if data.get('username') == 'admin' and data.get('password') == 'password123':
            token = generate_jwt_token(
                user_id='123',
                username='admin',
                additional_claims={'role': 'admin', 'permissions': ['read', 'write']}
            )
            return jsonify({
                'token': token,
                'token_type': 'Bearer',
                'expires_in': TOKEN_EXPIRY_HOURS * 3600
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    
    @app.route('/protected', methods=['GET'])
    @require_auth
    def protected_route():
        """Example protected route that requires valid JWT."""
        return jsonify({
            'message': f'Hello, {g.username}!',
            'user_id': g.user_id,
            'token_info': g.token_payload
        }), 200
    
    @app.route('/refresh', methods=['POST'])
    def refresh_token():
        """Example endpoint to refresh a JWT token."""
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Authorization header is missing'}), 401
        
        try:
            _, token = auth_header.split(' ', 1)
            new_token = refresh_jwt_token(token)
            
            if new_token:
                return jsonify({
                    'token': new_token,
                    'token_type': 'Bearer',
                    'expires_in': TOKEN_EXPIRY_HOURS * 3600
                }), 200
            else:
                return jsonify({'error': 'Invalid token'}), 401
                
        except ValueError:
            return jsonify({'error': 'Invalid authorization header format'}), 401
    
    app.run(debug=True)