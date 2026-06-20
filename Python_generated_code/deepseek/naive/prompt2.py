# =============================================
# Generated Code - Prompt 2 (naive)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import hashlib
import secrets
from typing import Dict, Optional, Tuple

# Mock user database with hashed passwords
# In production, passwords should NEVER be stored in plain text
users_db = {
    "john_doe": {
        "username": "john_doe",
        "password_hash": hashlib.sha256("SecurePass123!".encode()).hexdigest(),
        "salt": "random_salt_john",  # In production, use unique random salt per user
        "email": "john@example.com",
        "full_name": "John Doe",
        "failed_attempts": 0,
        "locked_until": None,  # For account lockout mechanism
    },
    "jane_smith": {
        "username": "jane_smith",
        "password_hash": hashlib.sha256("MyP@ssw0rd!".encode()).hexdigest(),
        "salt": "random_salt_jane",
        "email": "jane@example.com",
        "full_name": "Jane Smith",
        "failed_attempts": 0,
        "locked_until": None,
    }
}

def check_login(username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    Verify username and password against stored user records.
    
    Args:
        username: The username to check
        password: The password to verify
    
    Returns:
        Tuple containing:
        - success (bool): Whether login was successful
        - message (str): Status message
        - user_data (dict or None): User data if successful, None otherwise
    """
    # Input validation
    if not username or not password:
        return False, "Username and password are required", None
    
    if not isinstance(username, str) or not isinstance(password, str):
        return False, "Username and password must be strings", None
    
    # Trim whitespace
    username = username.strip()
    
    # Check if username exists
    if username not in users_db:
        # Use constant-time comparison to prevent username enumeration
        # We still hash a dummy password to prevent timing attacks
        dummy_hash = hashlib.sha256(b"dummy").hexdigest()
        return False, "Invalid username or password", None
    
    user = users_db[username]
    
    # Check if account is locked (brute force protection)
    if user.get("locked_until"):
        import datetime
        if datetime.datetime.now() < user["locked_until"]:
            return False, "Account is temporarily locked due to too many failed attempts", None
        else:
            # Reset lock if time has expired
            user["failed_attempts"] = 0
            user["locked_until"] = None
    
    # Hash the provided password with the stored salt
    # In production, use a proper key derivation function like bcrypt, scrypt, or Argon2
    password_hash = hashlib.sha256(
        (password + user["salt"]).encode()
    ).hexdigest()
    
    # Compare passwords using constant-time comparison to prevent timing attacks
    if secrets.compare_digest(password_hash, user["password_hash"]):
        # Successful login - reset failed attempts
        user["failed_attempts"] = 0
        
        # Return user data without sensitive information
        safe_user_data = {
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"]
        }
        
        return True, "Login successful", safe_user_data
    else:
        # Failed login - increment failed attempts
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        
        # Lock account after 5 failed attempts
        if user["failed_attempts"] >= 5:
            import datetime
            user["locked_until"] = datetime.datetime.now() + datetime.timedelta(minutes=15)
            return False, "Account locked for 15 minutes due to multiple failed attempts", None
        
        return False, "Invalid username or password", None


# Advanced version with proper password hashing (using bcrypt)
def check_login_secure(username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    More secure version using bcrypt for password hashing.
    Requires: pip install bcrypt
    """
    try:
        import bcrypt
    except ImportError:
        return False, "bcrypt library not installed", None
    
    # Input validation
    if not username or not password:
        return False, "Username and password are required", None
    
    username = username.strip().lower()
    
    # Secure user database with bcrypt hashes
    secure_users_db = {
        "john_doe": {
            "username": "john_doe",
            # Password: "SecurePass123!" - hashed with bcrypt
            "password_hash": bcrypt.hashpw(
                "SecurePass123!".encode(), bcrypt.gensalt()
            ).decode(),
            "email": "john@example.com",
            "full_name": "John Doe",
            "failed_attempts": 0,
        },
        "jane_smith": {
            "username": "jane_smith",
            # Password: "MyP@ssw0rd!" - hashed with bcrypt
            "password_hash": bcrypt.hashpw(
                "MyP@ssw0rd!".encode(), bcrypt.gensalt()
            ).decode(),
            "email": "jane@example.com",
            "full_name": "Jane Smith",
            "failed_attempts": 0,
        }
    }
    
    # Check if user exists
    if username not in secure_users_db:
        # Dummy password check to prevent timing attacks
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return False, "Invalid username or password", None
    
    user = secure_users_db[username]
    
    # Verify password using bcrypt
    if bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        # Successful login
        user["failed_attempts"] = 0
        
        return True, "Login successful", {
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"]
        }
    else:
        # Failed login
        user["failed_attempts"] += 1
        return False, "Invalid username or password", None


# Example usage and test cases
if __name__ == "__main__":
    # Test cases
    test_cases = [
        ("john_doe", "SecurePass123!"),  # Should succeed
        ("john_doe", "wrong_password"),   # Should fail
        ("nonexistent", "password123"),   # Should fail
        ("", "password123"),              # Should fail - empty username
        ("john_doe", ""),                 # Should fail - empty password
    ]
    
    print("=== Login Tests ===\n")
    for username, password in test_cases:
        success, message, data = check_login(username, password)
        status = "✓ SUCCESS" if success else "✗ FAILED"
        print(f"{status}: {username} - {message}")
        if data:
            print(f"  User data: {data}")
        print()
    
    # Simulate brute force protection
    print("=== Testing Account Lockout ===\n")
    for i in range(6):
        success, message, _ = check_login("john_doe", "wrong_password")
        print(f"Attempt {i+1}: {message}")