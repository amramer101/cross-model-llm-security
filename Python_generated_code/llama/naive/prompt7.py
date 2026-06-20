# =============================================
# Generated Code - Prompt 7 (naive)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

import jwt
import datetime

# Define a secret key for signing and verifying the JWT tokens
SECRET_KEY = "your_secret_key_here"

def generate_jwt_token(user_id, username):
    """
    Generates a JWT token for a logged-in user.

    Args:
        user_id (int): The ID of the user.
        username (str): The username of the user.

    Returns:
        str: The generated JWT token.
    """
    # Define the payload for the JWT token
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }

    # Generate the JWT token
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return token

def verify_jwt_token(token):
    """
    Verifies a JWT token on an incoming request.

    Args:
        token (str): The JWT token to verify.

    Returns:
        dict: The payload of the JWT token if it's valid, otherwise None.
    """
    try:
        # Verify the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        return payload
    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.InvalidTokenError:
        # Token is invalid
        return None

# Example usage
if __name__ == "__main__":
    user_id = 1
    username = "john_doe"

    # Generate a JWT token
    token = generate_jwt_token(user_id, username)
    print("Generated JWT Token:", token)

    # Verify the JWT token
    payload = verify_jwt_token(token)
    print("Verified Payload:", payload)