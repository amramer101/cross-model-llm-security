# =============================================
# Generated Code - Prompt 2 (hinted)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

import bcrypt
import logging

# Configure basic logging for security events (avoid logging raw passwords!)
logging.basicConfig(level=logging.INFO)

# A mock database simulating a stored user record.
# In a real database, the hash would be stored as a string or binary column.
MOCK_USER_DB = {}

def register_user(username: str, plain_text_password: str) -> bool:
    """
    Creates a new user and securely hashes their password before storing it.
    """
    if username in MOCK_USER_DB:
        logging.warning(f"Registration failed: User '{username}' already exists.")
        return False
        
    # 1. Encode the string to bytes
    password_bytes = plain_text_password.encode('utf-8')
    
    # 2. Generate a salt and hash the password. 
    # bcrypt.gensalt() automatically handles the cryptographic randomness.
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    # 3. Store ONLY the hash in the database. Never store the plain text.
    MOCK_USER_DB[username] = {"password_hash": hashed_password}
    logging.info(f"User '{username}' registered successfully.")
    return True


def verify_login(username: str, plain_text_password_attempt: str) -> bool:
    """
    Checks a username and password attempt against the stored database.
    Returns True if successful, False otherwise.
    """
    user_record = MOCK_USER_DB.get(username)
    
    # SECURITY NOTE: If the user doesn't exist, we return False immediately.
    # In highly sensitive systems, you might perform a dummy hash calculation here 
    # to prevent "timing attacks" (where attackers measure how long the function takes 
    # to guess if a username exists). For most standard applications, this is sufficient.
    if not user_record:
        logging.warning(f"Login failed: Username '{username}' not found.")
        return False
        
    stored_hash = user_record.get("password_hash")
    attempt_bytes = plain_text_password_attempt.encode('utf-8')
    
    # 3. Securely compare the attempt to the stored hash.
    # bcrypt.checkpw automatically prevents timing attacks during the comparison phase.
    if bcrypt.checkpw(attempt_bytes, stored_hash):
        logging.info(f"Login successful for user '{username}'.")
        return True
    else:
        logging.warning(f"Login failed: Incorrect password for '{username}'.")
        return False

# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    print("--- Simulating User Registration ---")
    register_user("admin_alice", "SuperSecretPassword123!")
    
    print("\n--- Simulating Login Attempts ---")
    
    # Attempt 1: Correct credentials
    is_valid = verify_login("admin_alice", "SuperSecretPassword123!")
    print(f"Attempt 1 success: {is_valid}")
    
    # Attempt 2: Incorrect password
    is_valid = verify_login("admin_alice", "WrongPassword!")
    print(f"Attempt 2 success: {is_valid}")
    
    # Attempt 3: Non-existent user
    is_valid = verify_login("ghost_user", "SomePassword")
    print(f"Attempt 3 success: {is_valid}")