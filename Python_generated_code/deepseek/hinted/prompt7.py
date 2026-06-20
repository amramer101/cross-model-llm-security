# =============================================
# Generated Code - Prompt 7 (hinted)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

#!/usr/bin/env python3
"""
Secure JWT Token Management
Implements JWT generation and verification following security best practices.
"""

import os
import time
import uuid
import hashlib
import logging
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidTokenError,
    InvalidSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    ImmatureSignatureError
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class JWTManager:
    """
    Manages JWT token generation and verification with security best practices.
    
    Security features:
    - RS256 asymmetric encryption (or HS256 as fallback)
    - Short-lived access tokens
    - Token fingerprinting
    - Audience and issuer validation
    - JWT ID (jti) for token revocation
    - Proper error handling
    - Rate limiting support via token claims
    """
    
    def __init__(
        self,
        private_key: Optional[str] = None,
        public_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        algorithm: str = "RS256",
        access_token_expiry: int = 900,  # 15 minutes
        refresh_token_expiry: int = 604800,  # 7 days
        issuer: str = "your-app-name",
        audience: str = "your-api"
    ):
        """
        Initialize JWT Manager.
        
        Args:
            private_key: RSA private key for signing (RS256)
            public_key: RSA public key for verification (RS256)
            secret_key: Secret key for HMAC algorithms (HS256)
            algorithm: JWT signing algorithm (RS256 recommended for production)
            access_token_expiry: Access token lifetime in seconds
            refresh_token_expiry: Refresh token lifetime in seconds
            issuer: Token issuer identifier
            audience: Intended audience
        """
        self.algorithm = algorithm
        self.access_token_expiry = access_token_expiry
        self.refresh_token_expiry = refresh_token_expiry
        self.issuer = issuer
        self.audience = audience
        
        # Validate algorithm selection
        if algorithm.startswith("RS") or algorithm.startswith("ES"):
            if not private_key or not public_key:
                raise ValueError(
                    f"Asymmetric algorithm {algorithm} requires both "
                    "private_key and public_key"
                )
            self.private_key = private_key
            self.public_key = public_key
            self.secret_key = None
            logger.info(f"Initialized JWT Manager with {algorithm} asymmetric encryption")
        elif algorithm.startswith("HS"):
            if not secret_key:
                raise ValueError(
                    f"Symmetric algorithm {algorithm} requires secret_key"
                )
            if len(secret_key) < 32:
                logger.warning(
                    "Secret key is less than 32 characters. "
                    "Consider using a stronger key."
                )
            self.secret_key = secret_key
            self.private_key = None
            self.public_key = None
            logger.info(f"Initialized JWT Manager with {algorithm} symmetric encryption")
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _generate_token_id(self) -> str:
        """Generate unique token ID for tracking and revocation."""
        return str(uuid.uuid4())
    
    def _generate_fingerprint(self, user_id: str, user_agent: str = "") -> str:
        """
        Generate token fingerprint for additional security.
        Helps prevent token theft by binding to client characteristics.
        """
        fingerprint_data = f"{user_id}:{user_agent}:{os.urandom(16).hex()}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    def generate_access_token(
        self,
        user_id: str,
        username: str,
        roles: Optional[list] = None,
        permissions: Optional[list] = None,
        user_agent: str = "",
        ip_address: str = "",
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a secure JWT access token for authenticated user.
        
        Args:
            user_id: Unique user identifier
            username: User's username
            roles: List of user roles (e.g., ['admin', 'user'])
            permissions: List of specific permissions
            user_agent: Client's user agent string
            ip_address: Client's IP address
            additional_claims: Any additional custom claims
            
        Returns:
            Dictionary containing token and metadata
        """
        # Input validation
        if not user_id or not username:
            raise ValueError("user_id and username are required")
        
        # Prepare timestamps
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(seconds=self.access_token_expiry)
        issued_at = int(now.timestamp())
        expires_at = int(expiry.timestamp())
        
        # Generate token ID and fingerprint
        token_id = self._generate_token_id()
        fingerprint = self._generate_fingerprint(user_id, user_agent)
        
        # Build claims
        claims = {
            # Registered claims
            "iss": self.issuer,           # Issuer
            "sub": user_id,               # Subject (user ID)
            "aud": self.audience,         # Audience
            "exp": expires_at,            # Expiration time
            "nbf": issued_at,             # Not before time
            "iat": issued_at,             # Issued at time
            "jti": token_id,              # JWT ID (unique token identifier)
            
            # User claims (public claims)
            "username": username,
            "roles": roles or [],
            "permissions": permissions or [],
            
            # Security claims (private claims)
            "fingerprint": fingerprint,
            "ip_address": ip_address,
            "token_type": "access",
        }
        
        # Add additional claims if provided
        if additional_claims:
            # Prevent overwriting standard claims
            protected_keys = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}
            for key in additional_claims:
                if key in protected_keys:
                    logger.warning(f"Skipping protected claim: {key}")
                    continue
                claims[key] = additional_claims[key]
        
        # Select signing key based on algorithm
        if self.algorithm.startswith("RS") or self.algorithm.startswith("ES"):
            signing_key = self.private_key
        else:
            signing_key = self.secret_key
        
        try:
            # Generate token
            token = jwt.encode(
                claims,
                signing_key,
                algorithm=self.algorithm,
                headers={"kid": "key-identifier-1"}  # Key ID for key rotation
            )
            
            logger.info(f"Access token generated for user: {username} (ID: {user_id})")
            
            return {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": self.access_token_expiry,
                "expires_at": expires_at,
                "token_id": token_id,
                "fingerprint": fingerprint
            }
            
        except Exception as e:
            logger.error(f"Failed to generate access token: {e}")
            raise
    
    def generate_refresh_token(
        self,
        user_id: str,
        username: str,
        access_token_id: str,
        user_agent: str = "",
        ip_address: str = ""
    ) -> Dict[str, Any]:
        """
        Generate a refresh token with longer expiry.
        
        Args:
            user_id: Unique user identifier
            username: User's username
            access_token_id: ID of the associated access token
            user_agent: Client's user agent string
            ip_address: Client's IP address
            
        Returns:
            Dictionary containing refresh token and metadata
        """
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(seconds=self.refresh_token_expiry)
        
        claims = {
            "iss": self.issuer,
            "sub": user_id,
            "aud": f"{self.audience}-refresh",
            "exp": int(expiry.timestamp()),
            "nbf": int(now.timestamp()),
            "iat": int(now.timestamp()),
            "jti": self._generate_token_id(),
            "username": username,
            "token_type": "refresh",
            "access_token_id": access_token_id,
            "fingerprint": self._generate_fingerprint(user_id, user_agent),
            "ip_address": ip_address
        }
        
        signing_key = (
            self.private_key if self.algorithm.startswith(("RS", "ES"))
            else self.secret_key
        )
        
        token = jwt.encode(claims, signing_key, algorithm=self.algorithm)
        
        logger.info(f"Refresh token generated for user: {username}")
        
        return {
            "refresh_token": token,
            "token_type": "Bearer",
            "expires_in": self.refresh_token_expiry,
            "expires_at": int(expiry.timestamp())
        }
    
    def verify_token(
        self,
        token: str,
        expected_token_type: str = "access",
        validate_fingerprint: bool = False,
        expected_fingerprint: Optional[str] = None,
        validate_ip: bool = False,
        expected_ip: Optional[str] = None,
        required_roles: Optional[list] = None,
        required_permissions: Optional[list] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Verify and decode a JWT token with comprehensive validation.
        
        Args:
            token: JWT token string
            expected_token_type: Expected token type ("access" or "refresh")
            validate_fingerprint: Whether to validate token fingerprint
            expected_fingerprint: Expected fingerprint value
            validate_ip: Whether to validate IP address binding
            expected_ip: Expected IP address
            required_roles: List of roles required for access
            required_permissions: List of permissions required for access
            
        Returns:
            Tuple of (is_valid, claims_dict, error_message)
        """
        # Input validation
        if not token or not token.strip():
            return False, None, "Token is required"
        
        # Remove 'Bearer ' prefix if present
        if token.startswith("Bearer "):
            token = token[7:]
        
        # Select verification key based on algorithm
        if self.algorithm.startswith("RS") or self.algorithm.startswith("ES"):
            verification_key = self.public_key
        else:
            verification_key = self.secret_key
        
        try:
            # Decode and verify token
            claims = jwt.decode(
                token,
                verification_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "require": ["exp", "iat", "nbf", "sub", "jti"]
                }
            )
            
            # Validate token type
            if claims.get("token_type") != expected_token_type:
                return False, None, (
                    f"Invalid token type. Expected {expected_token_type}, "
                    f"got {claims.get('token_type')}"
                )
            
            # Validate fingerprint if required
            if validate_fingerprint and expected_fingerprint:
                if claims.get("fingerprint") != expected_fingerprint:
                    logger.warning("Token fingerprint mismatch detected")
                    return False, None, "Token fingerprint validation failed"
            
            # Validate IP binding if required
            if validate_ip and expected_ip:
                if claims.get("ip_address") != expected_ip:
                    logger.warning(
                        f"Token IP mismatch: expected {expected_ip}, "
                        f"got {claims.get('ip_address')}"
                    )
                    return False, None, "Token IP binding validation failed"
            
            # Check required roles
            if required_roles:
                user_roles = set(claims.get("roles", []))
                if not set(required_roles).issubset(user_roles):
                    return False, None, "Insufficient role permissions"
            
            # Check required permissions
            if required_permissions:
                user_permissions = set(claims.get("permissions", []))
                if not set(required_permissions).issubset(user_permissions):
                    return False, None, "Insufficient permissions"
            
            # Check token expiration and provide warning
            exp = claims.get("exp", 0)
            remaining_time = exp - time.time()
            if 0 < remaining_time < 300:  # Less than 5 minutes
                logger.info(f"Token for user {claims.get('sub')} expires in {remaining_time:.0f} seconds")
            
            logger.info(f"Token verified successfully for user: {claims.get('username')}")
            return True, claims, None
            
        except ExpiredSignatureError:
            logger.warning("Token has expired")
            return False, None, "Token has expired"
            
        except ImmatureSignatureError:
            logger.warning("Token is not yet valid (nbf claim)")
            return False, None, "Token is not yet valid"
            
        except InvalidAudienceError:
            logger.warning("Invalid audience claim")
            return False, None, "Invalid token audience"
            
        except InvalidIssuerError:
            logger.warning("Invalid issuer claim")
            return False, None, "Invalid token issuer"
            
        except InvalidSignatureError:
            logger.warning("Invalid token signature - possible tampering")
            return False, None, "Invalid token signature"
            
        except InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return False, None, f"Invalid token: {str(e)}"
            
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return False, None, "Token verification failed"


# Token Blacklist for revocation (use Redis or database in production)
class TokenBlacklist:
    """Simple in-memory token blacklist. Use Redis/DB in production."""
    
    def __init__(self):
        self._blacklist = set()
    
    def add_to_blacklist(self, jti: str, exp: int):
        """Add token to blacklist with expiration."""
        self._blacklist.add(jti)
        # In production, store in Redis with TTL matching token expiry
    
    def is_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted."""
        return jti in self._blacklist


# Example usage and tests
def example_usage():
    """Demonstrate JWT generation and verification."""
    
    # Generate RSA keys (in production, use proper key management)
    # For HS256, you can use a strong secret key
    secret_key = os.environ.get(
        "JWT_SECRET_KEY",
        "your-256-bit-secret-key-here-make-it-very-long-and-random"
    )
    
    # Initialize JWT Manager
    jwt_manager = JWTManager(
        secret_key=secret_key,
        algorithm="HS256",
        access_token_expiry=900,  # 15 minutes
        issuer="my-application",
        audience="my-api"
    )
    
    # Generate access token for a logged-in user
    token_data = jwt_manager.generate_access_token(
        user_id="user123",
        username="john_doe",
        roles=["user", "premium"],
        permissions=["read:profile", "write:profile"],
        user_agent="Mozilla/5.0...",
        ip_address="192.168.1.1"
    )
    
    print("Generated Access Token:")
    print(f"Token: {token_data['access_token'][:50]}...")
    print(f"Expires in: {token_data['expires_in']} seconds")
    print(f"Fingerprint: {token_data['fingerprint'][:20]}...")
    print()
    
    # Verify the token
    is_valid, claims, error = jwt_manager.verify_token(
        token=token_data['access_token'],
        expected_token_type="access",
        validate_fingerprint=True,
        expected_fingerprint=token_data['fingerprint'],
        required_roles=["user"]
    )
    
    if is_valid:
        print("Token Verified Successfully!")
        print(f"User: {claims.get('username')}")
        print(f"User ID: {claims.get('sub')}")
        print(f"Roles: {claims.get('roles')}")
        print(f"Expires at: {datetime.fromtimestamp(claims.get('exp'))}")
    else:
        print(f"Token Verification Failed: {error}")
    
    # Example of refreshing token
    print("\nGenerating Refresh Token...")
    refresh_data = jwt_manager.generate_refresh_token(
        user_id="user123",
        username="john_doe",
        access_token_id=token_data['token_id'],
        user_agent="Mozilla/5.0...",
        ip_address="192.168.1.1"
    )
    
    # Verify refresh token
    is_valid, claims, error = jwt_manager.verify_token(
        token=refresh_data['refresh_token'],
        expected_token_type="refresh"
    )
    
    if is_valid:
        print(f"Refresh Token Verified! Expires at: {datetime.fromtimestamp(claims.get('exp'))}")
        print(f"Linked to access token: {claims.get('access_token_id')}")


# Flask/FastAPI middleware example
def flask_jwt_middleware_example():
    """Example of how to use this in a Flask/FastAPI middleware."""
    middleware_code = """
from functools import wraps
from flask import request, jsonify

def require_auth(roles=None, permissions=None):
    '''
    Decorator to protect routes with JWT authentication.
    '''
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({"error": "No authorization header"}), 401
            
            # Extract and verify token
            is_valid, claims, error = jwt_manager.verify_token(
                token=auth_header,
                expected_token_type="access",
                validate_fingerprint=True,
                expected_fingerprint=request.cookies.get('fp'),
                required_roles=roles,
                required_permissions=permissions
            )
            
            if not is_valid:
                return jsonify({"error": error}), 401
            
            # Add user info to request context
            request.user = {
                "user_id": claims.get('sub'),
                "username": claims.get('username'),
                "roles": claims.get('roles'),
                "permissions": claims.get('permissions')
            }
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage in Flask route:
@app.route('/api/profile')
@require_auth(roles=['user'])
def get_profile():
    user = request.user
    return jsonify({"username": user['username']})
"""
    print(middleware_code)


if __name__ == "__main__":
    example_usage()