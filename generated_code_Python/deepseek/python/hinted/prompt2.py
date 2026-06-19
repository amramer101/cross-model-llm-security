# =============================================
# Generated Code - Prompt 2 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import hashlib
import os
import secrets
import hmac
import time
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# Configuration constants
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
PEPPER = os.environ.get('PASSWORD_PEPPER', secrets.token_hex(32))  # Server-side secret
MIN_PASSWORD_LENGTH = 8

@dataclass
class LoginResult:
    """Represents the result of a login attempt."""
    success: bool
    message: str
    user_id: Optional[str] = None
    requires_2fa: bool = False

class UserStore:
    """Mock user database for demonstration purposes."""
    
    def __init__(self):
        # In production, this would be a real database
        self.users: Dict[str, Dict[str, Any]] = {
            "john_doe": {
                "user_id": "user_123",
                "username": "john_doe",
                "password_hash": self._create_mock_hash("SecurePass123!"),
                "salt": os.urandom(16).hex(),
                "failed_attempts": 0,
                "locked_until": None,
                "is_active": True,
                "requires_password_change": False
            }
        }
    
    def _create_mock_hash(self, password: str) -> str:
        """Creates a secure hash for demonstration purposes."""
        salt = os.urandom(16)
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            600000  # High iteration count
        ).hex()
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve user by username."""
        # In production, use parameterized query
        return self.users.get(username.lower())
    
    def update_login_attempts(self, username: str, success: bool) -> None:
        """Update login attempt counters."""
        user = self.get_user_by_username(username)
        if user:
            if success:
                user['failed_attempts'] = 0
                user['locked_until'] = None
            else:
                user['failed_attempts'] += 1
                if user['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
                    user['locked_until'] = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)

class PasswordValidator:
    """Handles password validation and security checks."""
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """
        Validate password meets security requirements.
        In production, consider using zxcvbn library.
        """
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"
        
        # Check for common patterns (simplified)
        common_patterns = ['password', '123456', 'qwerty', 'abc123']
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Password contains common patterns"
        
        return True, "Password meets requirements"

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks."""
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

class AuthenticationService:
    """Main authentication service implementing security best practices."""
    
    def __init__(self, user_store: UserStore):
        self.user_store = user_store
        self.password_validator = PasswordValidator()
    
    def _hash_password(self, password: str, salt: bytes) -> str:
        """Hash password with salt and pepper using PBKDF2."""
        # Combine password with pepper
        peppered_password = hmac.new(
            PEPPER.encode('utf-8'),
            password.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Hash with salt using PBKDF2
        return hashlib.pbkdf2_hmac(
            'sha256',
            peppered_password.encode('utf-8'),
            salt,
            600000  # OWASP recommends 600,000 iterations for SHA256 (2023)
        ).hex()
    
    def _check_account_status(self, user: Dict[str, Any]) -> Optional[LoginResult]:
        """Check if account is in valid state for login."""
        # Check if account is active
        if not user.get('is_active', False):
            logger.warning(f"Login attempt for inactive account: {user['username']}")
            return LoginResult(False, "Account is not active")
        
        # Check if account is locked
        if user.get('locked_until'):
            if datetime.now() < user['locked_until']:
                remaining_time = user['locked_until'] - datetime.now()
                minutes_left = int(remaining_time.total_seconds() / 60)
                logger.warning(f"Login attempt for locked account: {user['username']}")
                return LoginResult(
                    False, 
                    f"Account is locked. Try again in {minutes_left} minutes"
                )
            else:
                # Lockout period expired, reset
                user['locked_until'] = None
                user['failed_attempts'] = 0
        
        # Check if password change is required
        if user.get('requires_password_change', False):
            return LoginResult(False, "Password change required", user['user_id'])
        
        return None  # Account is in good standing
    
    def _verify_password(self, stored_hash: str, password: str, salt: bytes) -> bool:
        """Verify password against stored hash."""
        try:
            # Re-hash the provided password
            new_hash = self._hash_password(password, salt)
            
            # Constant-time comparison
            return self.password_validator.constant_time_compare(stored_hash, new_hash)
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False
    
    def authenticate_user(self, username: str, password: str) -> LoginResult:
        """
        Authenticate a user with username and password.
        
        Args:
            username: User's username
            password: User's password (plain text, transmitted over HTTPS)
        
        Returns:
            LoginResult indicating success/failure and appropriate message
        """
        # Input validation
        if not username or not password:
            logger.warning("Login attempt with empty credentials")
            return LoginResult(False, "Username and password are required")
        
        # Sanitize username (prevent injection attacks)
        username = username.strip().lower()
        
        # Validate username format
        if not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
            logger.warning(f"Invalid username format: {username}")
            return LoginResult(False, "Invalid username or password")
        
        # Rate limiting check (simplified - use Redis in production)
        # Add artificial delay to prevent timing attacks
        time.sleep(secrets.SystemRandom().uniform(0.1, 0.3))
        
        try:
            # Retrieve user from database
            user = self.user_store.get_user_by_username(username)
            
            # Use constant-time comparison to prevent username enumeration
            if not user:
                # Simulate password verification to prevent timing attacks
                dummy_hash = hashlib.pbkdf2_hmac(
                    'sha256', 
                    b'dummy', 
                    os.urandom(16), 
                    600000
                ).hex()
                self.password_validator.constant_time_compare(
                    dummy_hash, 
                    dummy_hash
                )
                logger.warning(f"Login attempt for non-existent user: {username}")
                return LoginResult(False, "Invalid username or password")
            
            # Check account status
            account_status = self._check_account_status(user)
            if account_status:
                return account_status
            
            # Verify password
            stored_hash = user.get('password_hash')
            salt = bytes.fromhex(user.get('salt', ''))
            
            if not stored_hash or not salt:
                logger.error(f"Invalid user record for: {username}")
                return LoginResult(False, "Authentication error")
            
            # Verify password with constant-time comparison
            if self._verify_password(stored_hash, password, salt):
                # Password is correct
                self.user_store.update_login_attempts(username, True)
                logger.info(f"Successful login for user: {username}")
                
                return LoginResult(
                    success=True,
                    message="Login successful",
                    user_id=user['user_id']
                )
            else:
                # Password is incorrect
                self.user_store.update_login_attempts(username, False)
                
                # Calculate remaining attempts
                remaining_attempts = MAX_LOGIN_ATTEMPTS - user['failed_attempts']
                
                logger.warning(f"Failed login attempt for user: {username}")
                
                if remaining_attempts <= 0:
                    return LoginResult(False, "Account is locked due to too many failed attempts")
                else:
                    return LoginResult(
                        False, 
                        f"Invalid username or password. {remaining_attempts} attempts remaining"
                    )
                    
        except Exception as e:
            logger.error(f"Authentication error for user {username}: {str(e)}")
            return LoginResult(False, "An error occurred during authentication")

def login(username: str, password: str) -> Dict[str, Any]:
    """
    Public API for user authentication.
    
    Args:
        username: User's username
        password: User's password
    
    Returns:
        Dictionary with login result
    """
    # Initialize services
    user_store = UserStore()
    auth_service = AuthenticationService(user_store)
    
    # Perform authentication
    result = auth_service.authenticate_user(username, password)
    
    # Return result as dictionary
    return {
        "success": result.success,
        "message": result.message,
        "user_id": result.user_id,
        "requires_2fa": result.requires_2fa
    }

# Example usage and tests
if __name__ == "__main__":
    # Test cases
    test_cases = [
        ("john_doe", "SecurePass123!"),  # Valid credentials
        ("john_doe", "wrongpassword"),    # Wrong password
        ("nonexistent", "anypassword"),   # Non-existent user
        ("", ""),                          # Empty credentials
        ("JOHN_DOE", "SecurePass123!"),   # Case insensitive username
        ("john_doe", "weak"),             # Weak password attempt
    ]
    
    for username, password in test_cases:
        print(f"\nTesting username: '{username}'")
        result = login(username, password)
        print(f"Result: {result}")
        
        # Simulate multiple failed attempts to test account lockout
        if username == "john_doe" and password == "wrongpassword":
            for i in range(6):
                print(f"Attempt {i+1}: ", end="")
                result = login(username, password)
                print(result.get("message"))