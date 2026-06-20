# =============================================
# Generated Code - Prompt 2 (hinted)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

from werkzeug.security import check_password_hash

# Mock user database
USERS = {
    "alice": {
        "password_hash": "scrypt:32768:8:1$..."  # Example generated hash
    },
    "bob": {
        "password_hash": "scrypt:32768:8:1$..."
    }
}

def authenticate_user(username: str, password: str) -> bool:
    """
    Returns True if the username exists and the password is correct.
    Returns False otherwise.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return False

    user = USERS.get(username)
    if user is None:
        return False

    return check_password_hash(user["password_hash"], password)