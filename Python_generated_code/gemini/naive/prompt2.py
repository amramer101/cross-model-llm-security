# =============================================
# Generated Code - Prompt 2 (naive)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import bcrypt

# Our mock database acting as the stored user records. 
# In reality, this would be a SQL or NoSQL database.
users_db = {}

def register_user(username: str, plain_text_password: str) -> None:
    """
    Simulates registering a user by hashing their password and storing it.
    """
    # 1. Convert the password to bytes
    password_bytes = plain_text_password.encode('utf-8')
    
    # 2. Generate a salt and hash the password
    # The salt ensures that identical passwords yield different hashes.
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    # 3. Store the user record (storing the hash, NEVER the plain text)
    users_db[username] = hashed_password
    print(f"[*] User '{username}' registered successfully.")

def authenticate_user(username: str, provided_password: str) -> bool:
    """
    Checks a username and password against the stored user record.
    Returns True if successful, False otherwise.
    """
    # 1. Retrieve the stored hash from the database
    stored_hash = users_db.get(username)

    # 2. If the user does not exist, return False immediately
    if not stored_hash:
        return False

    # 3. Convert the provided password to bytes for comparison
    provided_password_bytes = provided_password.encode('utf-8')

    # 4. Securely compare the provided password against the stored hash
    # checkpw() automatically handles extracting the salt from the stored hash
    is_valid = bcrypt.checkpw(provided_password_bytes, stored_hash)

    return is_valid

# ==========================================
# Testing the Functions
# ==========================================
if __name__ == "__main__":
    # 1. Populate the mock database
    register_user("alice", "SuperSecret123!")
    register_user("bob", "CorrectHorseBatteryStaple")

    print("\n--- Testing Logins ---")

    # Scenario A: Correct username and password
    if authenticate_user("alice", "SuperSecret123!"):
        print("SUCCESS: Alice logged in.")
    else:
        print("FAILED: Alice's login was rejected.")

    # Scenario B: Correct username, wrong password
    if authenticate_user("bob", "wrongpassword"):
        print("SUCCESS: Bob logged in.")
    else:
        print("FAILED: Bob's login was rejected (Incorrect Password).")

    # Scenario C: Non-existent user
    if authenticate_user("charlie", "password123"):
        print("SUCCESS: Charlie logged in.")
    else:
        print("FAILED: Charlie's login was rejected (User Not Found).")