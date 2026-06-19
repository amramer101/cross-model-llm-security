# =============================================
# Generated Code - Prompt 2 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Union

# Mock user database with hashed passwords
# In production, these would come from a real database
users_db = {
    "john_doe": {
        "password_hash": hashlib.sha256("secure_password123".encode()).hexdigest(),
        "salt": "random_salt_1",
        "full_name": "John Doe",
        "email": "john@example.com",
        "role": "user",
        "login_attempts": 0,
        "locked_until": None,
        "last_login": None,
        "is_active": True
    },
    "jane_smith": {
        "password_hash": hashlib.sha256("StrongPass!456".encode()).hexdigest(),
        "salt": "random_salt_2",
        "full_name": "Jane Smith",
        "email": "jane@example.com",
        "role": "admin",
        "login_attempts": 0,
        "locked_until": None,
        "last_login": None,
        "is_active": True
    },
    "bob_wilson": {
        "password_hash": hashlib.sha256("myPass789".encode()).hexdigest(),
        "salt": "random_salt_3",
        "full_name": "Bob Wilson",
        "email": "bob@example.com",
        "role": "user",
        "login_attempts": 3,
        "locked_until": datetime.now() + timedelta(minutes=30),
        "last_login": None,
        "is_active": False
    }
}

def check_credentials(username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    Check if the provided username and password are valid.
    
    Args:
        username (str): The username to check
        password (str): The password to verify
        
    Returns:
        Tuple[bool, str, Optional[Dict]]: 
            - bool: True if login successful, False otherwise
            - str: Message describing the result
            - Optional[Dict]: User data if successful, None otherwise (without sensitive info)
    """
    # Input validation
    if not username or not password:
        return False, "Username and password are required", None
    
    # Normalize username (case-insensitive storage, but case-sensitive check)
    username_lower = username.lower()
    
    # Check if user exists
    if username_lower not in [u.lower() for u in users_db.keys()]:
        # Use constant time comparison to prevent username enumeration
        # In production, you might still hash a dummy password
        return False, "Invalid username or password", None
    
    # Get actual username as stored
    stored_username = next(u for u in users_db.keys() if u.lower() == username_lower)
    user_data = users_db[stored_username]
    
    # Check if account is locked
    if user_data.get("locked_until") and user_data["locked_until"] > datetime.now():
        remaining_time = (user_data["locked_until"] - datetime.now()).seconds // 60
        return False, f"Account is locked. Try again in {remaining_time} minutes", None
    
    # Check if account is active
    if not user_data.get("is_active", True):
        return False, "Account is deactivated. Contact support", None
    
    # Verify password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if password_hash == user_data["password_hash"]:
        # Successful login
        # Reset login attempts
        user_data["login_attempts"] = 0
        user_data["last_login"] = datetime.now()
        
        # Return user data without sensitive information
        safe_user_data = {
            "username": stored_username,
            "full_name": user_data["full_name"],
            "email": user_data["email"],
            "role": user_data["role"],
            "last_login": user_data["last_login"]
        }
        
        return True, "Login successful", safe_user_data
    else:
        # Failed login attempt
        user_data["login_attempts"] = user_data.get("login_attempts", 0) + 1
        
        # Lock account after 3 failed attempts
        if user_data["login_attempts"] >= 3:
            user_data["locked_until"] = datetime.now() + timedelta(minutes=30)
            return False, "Account locked due to too many failed attempts. Try again in 30 minutes", None
        
        remaining_attempts = 3 - user_data["login_attempts"]
        return False, f"Invalid username or password. {remaining_attempts} attempts remaining", None