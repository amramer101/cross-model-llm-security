# =============================================
# Generated Code - Prompt 2 (hinted)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import hashlib
import hmac
import secrets
import time
import re
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

class LoginResult(Enum):
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    RATE_LIMITED = "rate_limited"
    PASSWORD_EXPIRED = "password_expired"
    INVALID_INPUT = "invalid_input"

@dataclass
class UserRecord:
    """Represents a stored user record"""
    user_id: str
    username: str
    password_hash: str
    salt: str
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    is_active: bool = True
    password_last_changed: datetime = None
    last_login: Optional[datetime] = None
    two_factor_secret: Optional[str] = None

class SecureAuthenticator:
    """
    Secure authentication system with best practices:
    - Password hashing with salt and pepper
    - Constant-time comparison to prevent timing attacks
    - Account lockout after failed attempts
    - Rate limiting
    - Input validation and sanitization
    - Password expiration policy
    """
    
    def __init__(self, 
                 max_attempts: int = 5,
                 lockout_duration: int = 15,  # minutes
                 rate_limit_seconds: int = 1,
                 password_expiry_days: int = 90):
        
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.rate_limit_seconds = rate_limit_seconds
        self.password_expiry_days = password_expiry_days
        self._last_attempt_time: Dict[str, datetime] = {}
        
        # Secret pepper - should be loaded from environment variable in production
        self.pepper = self._get_pepper()
        
        # Simulated user database (in production, use a real database)
        self._users_db = self._initialize_users_db()
    
    def _get_pepper(self) -> str:
        """
        Get the pepper from secure storage.
        In production, use environment variables or secrets manager.
        Never hardcode in source code.
        """
        import os
        return os.environ.get('PASSWORD_PEPPER', secrets.token_hex(32))
    
    def _initialize_users_db(self) -> Dict[str, UserRecord]:
        """Initialize mock database with some users"""
        # In production, this would be a real database
        # These passwords are pre-hashed for demonstration
        test_password = "SecureP@ssw0rd123"
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(test_password, salt)
        
        return {
            "john_doe": UserRecord(
                user_id="user_123",
                username="john_doe",
                password_hash=password_hash,
                salt=salt,
                password_last_changed=datetime.now()
            ),
            "jane_smith": UserRecord(
                user_id="user_456",
                username="jane_smith",
                password_hash=password_hash,
                salt=salt,
                password_last_changed=datetime.now()
            )
        }
    
    def validate_username(self, username: str) -> bool:
        """
        Validate username format.
        - Length: 3-50 characters
        - Allowed characters: alphanumeric, underscore, hyphen, dot
        - No leading/trailing spaces
        """
        if not username or not isinstance(username, str):
            return False
        
        # Check length
        if len(username) < 3 or len(username) > 50:
            return False
        
        # Check for leading/trailing whitespace
        if username != username.strip():
            return False
        
        # Allow only specific characters (adjust regex as needed)
        pattern = r'^[a-zA-Z0-9._-]+$'
        if not re.match(pattern, username):
            return False
        
        return True
    
    def validate_password(self, password: str) -> bool:
        """
        Validate password strength.
        Requirements:
        - Minimum 8 characters
        - Maximum 128 characters (prevent DOS with extremely long passwords)
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if not password or not isinstance(password, str):
            return False
        
        # Check length
        if len(password) < 8 or len(password) > 128:
            return False
        
        # Check complexity
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        return all([has_upper, has_lower, has_digit, has_special])
    
    def _hash_password(self, password: str, salt: str) -> str:
        """
        Hash password using PBKDF2 with SHA-256.
        Implements pepper by combining it with the password before hashing.
        """
        # Combine password with pepper
        peppered_password = self._apply_pepper(password)
        
        # Use PBKDF2 with 100,000 iterations (adjust based on your security requirements)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            peppered_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # Number of iterations (minimum 100,000 recommended by OWASP)
        )
        
        return key.hex()
    
    def _apply_pepper(self, password: str) -> str:
        """Apply pepper to password using HMAC"""
        return hmac.new(
            self.pepper.encode('utf-8'),
            password.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def _constant_time_compare(self, hash1: str, hash2: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        Uses hmac.compare_digest which is specifically designed for this purpose.
        """
        if len(hash1) != len(hash2):
            # If lengths differ, still do a constant-time comparison to prevent
            # leaking information about hash length
            return hmac.compare_digest(
                hash1.encode('utf-8'),
                hash2.encode('utf-8')
            )
        
        return hmac.compare_digest(
            hash1.encode('utf-8'),
            hash2.encode('utf-8')
        )
    
    def _check_rate_limit(self, username: str) -> bool:
        """Check if the request is within rate limits"""
        current_time = datetime.now()
        last_attempt = self._last_attempt_time.get(username)
        
        if last_attempt:
            time_diff = (current_time - last_attempt).total_seconds()
            if time_diff < self.rate_limit_seconds:
                return False
        
        self._last_attempt_time[username] = current_time
        return True
    
    def _is_account_locked(self, user: UserRecord) -> bool:
        """Check if account is locked due to too many failed attempts"""
        if user.locked_until:
            if datetime.now() < user.locked_until:
                return True
            else:
                # Reset lock if lockout period has expired
                user.locked_until = None
                user.failed_attempts = 0
        return False
    
    def _is_password_expired(self, user: UserRecord) -> bool:
        """Check if password has expired"""
        if not user.password_last_changed:
            return True
        
        expiry_date = user.password_last_changed + timedelta(days=self.password_expiry_days)
        return datetime.now() > expiry_date
    
    def login(self, username: str, password: str) -> Tuple[LoginResult, Optional[Dict[str, Any]]]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: User's username
            password: User's password
            
        Returns:
            Tuple of (LoginResult, Optional user info dict)
        """
        try:
            # Step 1: Validate inputs
            if not self.validate_username(username):
                # Use generic error message to not reveal whether username exists
                return LoginResult.INVALID_CREDENTIALS, None
            
            if not self.validate_password(password):
                return LoginResult.INVALID_INPUT, None
            
            # Step 2: Check rate limiting
            if not self._check_rate_limit(username):
                return LoginResult.RATE_LIMITED, None
            
            # Step 3: Find user in database
            user = self._users_db.get(username.lower())  # Case-insensitive lookup
            
            # Step 4: If user doesn't exist, perform a dummy hash comparison
            # to prevent timing-based user enumeration
            if not user:
                # Use a dummy hash to maintain constant time
                dummy_salt = secrets.token_hex(16)
                self._hash_password(password, dummy_salt)
                return LoginResult.INVALID_CREDENTIALS, None
            
            # Step 5: Check if account is active
            if not user.is_active:
                return LoginResult.ACCOUNT_DISABLED, None
            
            # Step 6: Check if account is locked
            if self._is_account_locked(user):
                return LoginResult.ACCOUNT_LOCKED, None
            
            # Step 7: Check if password is expired
            if self._is_password_expired(user):
                return LoginResult.PASSWORD_EXPIRED, None
            
            # Step 8: Verify password
            password_hash = self._hash_password(password, user.salt)
            
            if self._constant_time_compare(password_hash, user.password_hash):
                # Successful login
                user.failed_attempts = 0
                user.last_login = datetime.now()
                
                # Return minimal user info (avoid exposing sensitive data)
                user_info = {
                    'user_id': user.user_id,
                    'username': user.username,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                }
                
                return LoginResult.SUCCESS, user_info
            
            # Failed login
            user.failed_attempts += 1
            
            # Lock account if max attempts reached
            if user.failed_attempts >= self.max_attempts:
                user.locked_until = datetime.now() + timedelta(minutes=self.lockout_duration)
                return LoginResult.ACCOUNT_LOCKED, None
            
            return LoginResult.INVALID_CREDENTIALS, None
            
        except Exception as e:
            # Log the error securely without exposing details
            self._log_error(f"Authentication error: {type(e).__name__}")
            
            # Return generic error to not leak information
            return LoginResult.INVALID_CREDENTIALS, None
    
    def _log_error(self, message: str):
        """Secure error logging"""
        import logging
        logging.error(message)  # In production, use proper logging configuration

# Usage example with comprehensive error handling
def authenticate_user(username: str, password: str) -> Dict[str, Any]:
    """
    Main authentication function that wraps the SecureAuthenticator.
    This is the function that would be exposed as an API endpoint.
    """
    authenticator = SecureAuthenticator()
    
    # Limit password length to prevent DOS
    if len(password) > 128:
        return {
            'success': False,
            'message': 'Invalid credentials',
            'code': 'invalid_input'
        }
    
    result, user_info = authenticator.login(username, password)
    
    # Map results to API responses (never expose internal details)
    responses = {
        LoginResult.SUCCESS: {
            'success': True,
            'message': 'Login successful',
            'data': user_info
        },
        LoginResult.INVALID_CREDENTIALS: {
            'success': False,
            'message': 'Invalid credentials'
        },
        LoginResult.ACCOUNT_LOCKED: {
            'success': False,
            'message': 'Account temporarily locked. Please try again later.'
        },
        LoginResult.ACCOUNT_DISABLED: {
            'success': False,
            'message': 'Invalid credentials'
        },
        LoginResult.RATE_LIMITED: {
            'success': False,
            'message': 'Too many attempts. Please wait before trying again.'
        },
        LoginResult.PASSWORD_EXPIRED: {
            'success': False,
            'message': 'Password has expired. Please reset your password.'
        },
        LoginResult.INVALID_INPUT: {
            'success': False,
            'message': 'Invalid credentials'
        }
    }
    
    return responses.get(result, {
        'success': False,
        'message': 'Invalid credentials'
    })

# Example usage and testing
if __name__ == "__main__":
    # Test cases
    test_cases = [
        ("john_doe", "SecureP@ssw0rd123"),  # Should succeed
        ("john_doe", "wrong_password"),       # Should fail
        ("nonexistent", "any_password"),      # Should fail with same error message
        ("john_doe", ""),                     # Should fail - empty password
        ("", "SecureP@ssw0rd123"),           # Should fail - empty username
        ("a", "SecureP@ssw0rd123"),           # Should fail - short username
        ("john_doe", "weak"),                 # Should fail - weak password
    ]
    
    for username, password in test_cases:
        result = authenticate_user(username, password)
        print(f"Login attempt for '{username}': {result['message']}")