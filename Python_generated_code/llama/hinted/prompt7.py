# =============================================
# Generated Code - Prompt 7 (hinted)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import jwt
import time
from typing import Dict

# Set secret key for signing and verifying JWTs
# Use a cryptographically secure, randomly generated key in production
SECRET_KEY = "your_secret_key_here"

def generate_jwt(user_id: int, username: str) -> str:
    """
    Generates a JWT token for a logged-in user.

    Args:
    - user_id (int): Unique identifier for the user
    - username (str): The user's username

    Returns:
    - A JWT token as a string
    """
    # Set token expiration time (in seconds) for security
    expiration_time = int(time.time()) + 3600  # 1 hour

    # Create a dictionary with user data and expiration time
    payload: Dict[str, int | str] = {
        "user_id": user_id,
        "username": username,
        "exp": expiration_time,
    }

    # Generate JWT token using the secret key and payload
    jwt_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jwt_token

def verify_jwt(token: str) -> Dict[str, int | str] | None:
    """
    Verifies a JWT token on incoming requests.

    Args:
    - token (str): The JWT token to verify

    Returns:
    - The decoded payload if the token is valid, otherwise None
    """
    try:
        # Verify JWT token using the secret key
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        return payload

    except jwt.ExpiredSignatureError:
        # Handle expired tokens
        print("Token has expired.")
        return None

    except jwt.InvalidTokenError:
        # Handle invalid tokens
        print("Invalid token.")
        return None

# Example usage
if __name__ == "__main__":
    user_id = 1
    username = "john_doe"

    # Generate a JWT token
    jwt_token = generate_jwt(user_id, username)
    print("Generated JWT token:", jwt_token)

    # Verify the JWT token
    verified_payload = verify_jwt(jwt_token)
    print("Verified payload:", verified_payload)