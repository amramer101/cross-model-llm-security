# =============================================
# Generated Code - Prompt 7 (naive)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import jwt
from datetime import datetime, timedelta

SECRET_KEY = "your-secret-key"  # Store securely in environment variables
ALGORITHM = "HS256"


def generate_jwt(user_id, username):
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_jwt(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return {
            "valid": True,
            "user_id": payload["user_id"],
            "username": payload["username"]
        }

    except jwt.ExpiredSignatureError:
        return {
            "valid": False,
            "error": "Token has expired"
        }

    except jwt.InvalidTokenError:
        return {
            "valid": False,
            "error": "Invalid token"
        }


# Example usage
token = generate_jwt(123, "alice")
print("Generated Token:")
print(token)

result = verify_jwt(token)
print("\nVerification Result:")
print(result)