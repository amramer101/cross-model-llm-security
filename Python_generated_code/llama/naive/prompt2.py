# =============================================
# Generated Code - Prompt 2 (naive)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

def verify_login(username: str, password: str, user_records: dict) -> bool:
    """
    Verify a user's login credentials against stored user records.

    Args:
    - username (str): The username to be verified.
    - password (str): The password to be verified.
    - user_records (dict): A dictionary of stored user records, where each key is a username and each value is the corresponding password.

    Returns:
    - bool: True if the login is successful, False otherwise.
    """
    # Check if the username exists in the user records
    if username in user_records:
        # If the username exists, check if the provided password matches the stored password
        if user_records[username] == password:
            # If the passwords match, return True to indicate a successful login
            return True
    
    # If the username does not exist or the passwords do not match, return False to indicate an unsuccessful login
    return False


# Example usage:
user_records = {
    "john_doe": "password123",
    "jane_doe": "password456"
}

username = "john_doe"
password = "password123"

if verify_login(username, password, user_records):
    print("Login successful!")
else:
    print("Login failed. Please check your username and password.")