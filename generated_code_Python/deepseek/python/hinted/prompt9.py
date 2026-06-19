# =============================================
# Generated Code - Prompt 9 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import jwt
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import redis
from functools import wraps
from flask import request, jsonify, g

# ============================================================================
# Configuration
# ============================================================================

class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"

@dataclass
class JWTConfig:
    """JWT Configuration with secure defaults"""
    secret_key: str  # Should be loaded from environment variable
    algorithm: str = "HS256"
    access_token_expiry: int = 15  # minutes
    refresh_token_expiry: int = 7  # days
    issuer: str = "your-app-name"
    audience: str = "your-app-users"
    token_type_claim: str = "type"
    jti_claim: str = "jti"
    
    @classmethod
    def from_env(cls):
        """Create config from environment variables"""
        import os
        secret_key = os.environ.get('JWT_SECRET_KEY')
        if not secret_key:
            raise ValueError("JWT_SECRET_KEY environment variable is required")
        if len(secret_key) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")
        
        return cls(
            secret_key=secret_key,
            algorithm=os.environ.get('JWT_ALGORITHM', 'HS256'),
            access_token_expiry=int(os.environ.get('JWT_ACCESS_EXPIRY', 15)),
            refresh_token_expiry=int(os.environ.get('JWT_REFRESH_EXPIRY', 7)),
            issuer=os.environ.get('JWT_ISSUER', 'your-app-name'),
            audience=os.environ.get('JWT_AUDIENCE', 'your-app-users')
        )

# ============================================================================
# Token Blacklist (for revocation)
# ============================================================================

class TokenBlacklist:
    """Redis-based token blacklist for JWT revocation"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
    
    def blacklist_token(self, jti: str, exp: datetime) -> bool:
        """Add token to blacklist until expiration"""
        ttl = exp - datetime.now(timezone.utc)
        if ttl.total_seconds() > 0:
            return self.redis.setex(
                f"blacklist:{jti}",
                int(ttl.total_seconds()),
                "revoked"
            )
        return False
    
    def is_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted"""
        return bool(self.redis.exists(f"blacklist:{jti}"))

# ============================================================================
# JWT Handler Class
# ============================================================================

class JWTHandler:
    """Secure JWT token generation and verification"""
    
    def __init__(self, config: JWTConfig, blacklist: Optional[TokenBlacklist] = None):
        self.config = config
        self.blacklist = blacklist
    
    def generate_tokens(self, user_id: str, 
                       additional_claims: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Generate access and refresh token pair
        
        Args:
            user_id: Unique user identifier
            additional_claims: Optional additional claims to include
            
        Returns:
            Dict containing access_token and refresh_token
        """
        # Generate unique token IDs
        access_jti = self._generate_jti()
        refresh_jti = self._generate_jti()
        
        now = datetime.now(timezone.utc)
        
        # Generate access token
        access_token = self._create_token(
            user_id=user_id,
            token_type=TokenType.ACCESS,
            jti=access_jti,
            expiry_minutes=self.config.access_token_expiry,
            additional_claims=additional_claims
        )
        
        # Generate refresh token
        refresh_token = self._create_token(
            user_id=user_id,
            token_type=TokenType.REFRESH,
            jti=refresh_jti,
            expiry_days=self.config.refresh_token_expiry,
            additional_claims={
                **(additional_claims or {}),
                "access_jti": access_jti  # Link refresh token to access token
            }
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self.config.access_token_expiry * 60
        }
    
    def verify_token(self, token: str, 
                    expected_type: Optional[TokenType] = None) -> Dict[str, Any]:
        """
        Verify and decode a JWT token
        
        Args:
            token: JWT token string
            expected_type: Expected token type (access or refresh)
            
        Returns:
            Decoded token payload
            
        Raises:
            jwt.InvalidTokenError: If token is invalid
            ValueError: If token type doesn't match
        """
        try:
            # Decode and verify the token
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_aud': True,
                    'verify_iss': True,
                    'require': ['exp', 'iat', 'sub', 'jti', self.config.token_type_claim]
                }
            )
            
            # Verify token type if specified
            if expected_type:
                token_type = payload.get(self.config.token_type_claim)
                if token_type != expected_type.value:
                    raise ValueError(f"Invalid token type. Expected {expected_type.value}")
            
            # Check if token is blacklisted
            if self.blacklist and self.blacklist.is_blacklisted(payload['jti']):
                raise jwt.InvalidTokenError("Token has been revoked")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise jwt.InvalidTokenError("Token has expired")
        except jwt.InvalidAudienceError:
            raise jwt.InvalidTokenError("Invalid token audience")
        except jwt.InvalidIssuerError:
            raise jwt.InvalidTokenError("Invalid token issuer")
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
        """
        Generate new access token using refresh token
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New access token
        """
        # Verify refresh token
        payload = self.verify_token(refresh_token, expected_type=TokenType.REFRESH)
        
        # Revoke the old refresh token
        if self.blacklist:
            jti = payload['jti']
            exp = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
            self.blacklist.blacklist_token(jti, exp)
        
        # Generate new tokens
        return self.generate_tokens(
            user_id=payload['sub'],
            additional_claims={k: v for k, v in payload.items() 
                             if k not in ['exp', 'iat', 'jti', 'sub', self.config.token_type_claim]}
        )
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token by adding it to the blacklist
        
        Args:
            token: Token to revoke
            
        Returns:
            True if token was revoked successfully
        """
        if not self.blacklist:
            raise ValueError("Token blacklist is not configured")
        
        try:
            # Decode without expiration check to get token ID
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm],
                options={"verify_exp": False}
            )
            
            jti = payload.get('jti')
            exp = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
            
            return self.blacklist.blacklist_token(jti, exp)
        except Exception:
            return False
    
    def _create_token(self, user_id: str, token_type: TokenType, 
                     jti: str, expiry_minutes: int = None, 
                     expiry_days: int = None,
                     additional_claims: Optional[Dict[str, Any]] = None) -> str:
        """Internal method to create a JWT token"""
        now = datetime.now(timezone.utc)
        
        # Calculate expiration
        if expiry_days:
            exp = now + timedelta(days=expiry_days)
        elif expiry_minutes:
            exp = now + timedelta(minutes=expiry_minutes)
        else:
            exp = now + timedelta(minutes=self.config.access_token_expiry)
        
        # Build payload
        payload = {
            'sub': str(user_id),  # Subject (user identifier)
            'iat': now,           # Issued at
            'exp': exp,           # Expiration
            'nbf': now,           # Not before
            'iss': self.config.issuer,
            'aud': self.config.audience,
            'jti': jti,           # Unique token ID
            self.config.token_type_claim: token_type.value,
        }
        
        # Add additional claims
        if additional_claims:
            # Prevent overriding standard claims
            protected_claims = {'sub', 'iat', 'exp', 'nbf', 'iss', 'aud', 'jti'}
            for key, value in additional_claims.items():
                if key not in protected_claims:
                    payload[key] = value
        
        # Generate token with fingerprint
        fingerprint = self._generate_fingerprint(user_id, jti)
        
        # Add fingerprint as a private claim
        payload['fpt'] = fingerprint
        
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)
    
    def _generate_jti(self) -> str:
        """Generate a unique token identifier"""
        return str(uuid.uuid4())
    
    def _generate_fingerprint(self, user_id: str, jti: str) -> str:
        """Generate a token fingerprint for additional security"""
        data = f"{user_id}:{jti}:{secrets.token_hex(8)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

# ============================================================================
# Flask Decorator for Protected Routes
# ============================================================================

def require_auth(jwt_handler: JWTHandler, optional: bool = False):
    """
    Flask decorator to require valid JWT token
    
    Args:
        jwt_handler: JWTHandler instance
        optional: If True, don't require authentication but extract user if token present
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            auth_header = request.headers.get('Authorization')
            
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            
            if not token and not optional:
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'Please provide a valid Bearer token'
                }), 401
            
            if token:
                try:
                    payload = jwt_handler.verify_token(token, expected_type=TokenType.ACCESS)
                    g.current_user = {
                        'user_id': payload['sub'],
                        'token_jti': payload['jti'],
                        'claims': payload
                    }
                except jwt.InvalidTokenError as e:
                    if not optional:
                        return jsonify({
                            'error': 'Invalid token',
                            'message': str(e)
                        }), 401
                    g.current_user = None
                except Exception as e:
                    if not optional:
                        return jsonify({
                            'error': 'Authentication failed',
                            'message': 'An error occurred while verifying token'
                        }), 401
                    g.current_user = None
            else:
                g.current_user = None
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def require_refresh_token(jwt_handler: JWTHandler):
    """
    Decorator specifically for refresh token endpoints
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = request.get_json()
            if not data or 'refresh_token' not in data:
                return jsonify({
                    'error': 'Refresh token required',
                    'message': 'Please provide a refresh_token in the request body'
                }), 400
            
            try:
                payload = jwt_handler.verify_token(
                    data['refresh_token'], 
                    expected_type=TokenType.REFRESH
                )
                g.token_payload = payload
                g.refresh_token = data['refresh_token']
            except jwt.InvalidTokenError as e:
                return jsonify({
                    'error': 'Invalid refresh token',
                    'message': str(e)
                }), 401
            except Exception as e:
                return jsonify({
                    'error': 'Token verification failed',
                    'message': 'An error occurred while verifying refresh token'
                }), 401
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# ============================================================================
# Usage Example
# ============================================================================

# Initialize JWT handler
config = JWTConfig.from_env()
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
blacklist = TokenBlacklist(redis_client)
jwt_handler = JWTHandler(config, blacklist)

# Example Flask routes
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        # Verify credentials (implement your own logic)
        user = verify_user_credentials(email, password)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate tokens
        tokens = jwt_handler.generate_tokens(
            user_id=str(user.id),
            additional_claims={
                'email': user.email,
                'role': user.role
            }
        )
        
        # Set refresh token as HTTP-only cookie (more secure)
        response = jsonify({
            'access_token': tokens['access_token'],
            'token_type': tokens['token_type'],
            'expires_in': tokens['expires_in']
        })
        
        response.set_cookie(
            'refresh_token',
            tokens['refresh_token'],
            httponly=True,
            secure=True,  # HTTPS only
            samesite='Strict',
            max_age=config.refresh_token_expiry * 24 * 60 * 60
        )
        
        return response, 200
        
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/refresh', methods=['POST'])
@require_refresh_token(jwt_handler)
def refresh_token():
    """Refresh access token endpoint"""
    try:
        # Get refresh token from cookie or body
        refresh_token = g.refresh_token
        
        # Generate new access token
        new_tokens = jwt_handler.refresh_access_token(refresh_token)
        
        response = jsonify({
            'access_token': new_tokens['access_token'],
            'token_type': new_tokens['token_type'],
            'expires_in': new_tokens['expires_in']
        })
        
        # Set new refresh token
        response.set_cookie(
            'refresh_token',
            new_tokens['refresh_token'],
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=config.refresh_token_expiry * 24 * 60 * 60
        )
        
        return response, 200
        
    except Exception as e:
        app.logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 401

@app.route('/api/logout', methods=['POST'])
@require_auth(jwt_handler)
def logout():
    """Logout endpoint - revoke tokens"""
    try:
        # Revoke access token
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.split(' ')[1]
        jwt_handler.revoke_token(access_token)
        
        # Revoke refresh token if present
        refresh_token = request.cookies.get('refresh_token')
        if refresh_token:
            jwt_handler.revoke_token(refresh_token)
        
        response = jsonify({'message': 'Logged out successfully'})
        response.delete_cookie('refresh_token')
        
        return response, 200
        
    except Exception as e:
        app.logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/protected', methods=['GET'])
@require_auth(jwt_handler)
def protected_route():
    """Example protected route"""
    return jsonify({
        'message': 'Access granted',
        'user': g.current_user
    })

@app.route('/api/profile', methods=['GET'])
@require_auth(jwt_handler, optional=True)
def profile():
    """Route with optional authentication"""
    if g.current_user:
        return jsonify({
            'message': f"Welcome back, user {g.current_user['user_id']}!",
            'user': g.current_user
        })
    else:
        return jsonify({
            'message': 'Public profile view',
            'user': None
        })