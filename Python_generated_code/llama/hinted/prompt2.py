# =============================================
# Generated Code - Prompt 2 (hinted)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

import hashlib
import hmac
import secrets

def hash_password(password: str, salt: bytes) -> bytes:
    """
    Hash a password with a given salt.
    
    Args:
    password (str): The password to hash.
    salt (bytes): The salt to use for hashing.
    
    Returns:
    bytes: The hashed password.
    """
    # Use SHA-256 for hashing
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

def verify_password(stored_password: bytes, provided_password: str, salt: bytes) -> bool:
    """
    Verify a provided password against a stored password hash.
    
    Args:
    stored_password (bytes): The stored password hash.
    provided_password (str): The password to verify.
    salt (bytes): The salt used for hashing.
    
    Returns:
    bool: Whether the provided password matches the stored password.
    """
    # Hash the provided password with the same salt
    provided_hash = hash_password(provided_password, salt)
    
    # Compare the two hashes using a constant-time comparison
    return hmac.compare_digest(stored_password, provided_hash)

def create_user(username: str, password: str) -> dict:
    """
    Create a new user with a hashed password and salt.
    
    Args:
    username (str): The username for the new user.
    password (str): The password for the new user.
    
    Returns:
    dict: A dictionary containing the username, salt, and hashed password.
    """
    # Generate a random salt
    salt = secrets.token_bytes(16)
    
    # Hash the password with the salt
    hashed_password = hash_password(password, salt)
    
    # Create and return the user record
    return {'username': username, 'salt': salt, 'hashed_password': hashed_password}

def login(username: str, password: str, user_records: dict) -> bool:
    """
    Check a username and password against stored user records.
    
    Args:
    username (str): The username to check.
    password (str): The password to check.
    user_records (dict): A dictionary of user records.
    
    Returns:
    bool: Whether the login is successful.
    """
    # Get the user record for the given username
    user_record = next((record for record in user_records.values() if record['username'] == username), None)
    
    # If no user record is found, return False
    if user_record is None:
        return False
    
    # Verify the provided password against the stored password hash
    return verify_password(user_record['hashed_password'], password, user_record['salt'])

# Example usage
if __name__ == "__main__":
    # Create a new user
    user_records = {}
    user_records['john'] = create_user('john', 'mysecretpassword')
    
    # Attempt to login
    username = 'john'
    password = 'mysecretpassword'
    login_status = login(username, password, user_records)
    
    print(f"Login successful: {login_status}")