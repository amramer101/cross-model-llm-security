# =============================================
# Generated Code - Prompt 7 (naive)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import jwt
import os
from datetime import datetime, timedelta, timezone

# ==========================================
# Configuration
# ==========================================
# CRITICAL: In a real application, NEVER hardcode your secret key.
# Load it from an environment variable. If this key is compromised,
# attackers can forge valid tokens for any user.
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super_secret_development_key_123!")

# The algorithm used to sign the token. HS256 is the most common and standard.
ALGORITHM = "HS256"

# How long the token remains valid. Shorter is generally more secure.
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def generate_jwt(user_id: int, username: str) -> str:
    """
    Generates a JWT token for a specific user upon successful login.
    """
    # 1. Define the claims (the data stored inside the token)
    # Use timezone-aware UTC datetime for the expiration and issued-at times
    now = datetime.now(timezone.utc)
    expiration_time = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    payload = {
        "sub": str(user_id),        # 'sub' (Subject) is standard for the user ID
        "username": username,       # Custom claim
        "iat": now,                 # 'iat' (Issued At) time
        "exp": expiration_time      # 'exp' (Expiration Time) is crucial for security
    }

    # 2. Encode and sign the token
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    return token

def verify_jwt(token: str) -> dict:
    """
    Verifies a JWT token from an incoming request.
    Returns the decoded payload if valid, or a dictionary with an error message.
    """
    try:
        # 1. Decode the token
        # PyJWT automatically checks the 'exp' claim and signature
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        return {
            "valid": True,
            "payload": decoded_payload
        }
        
    except jwt.ExpiredSignatureError:
        # 2. Handle the case where the token's 'exp' time has passed
        return {
            "valid": False,
            "error": "Token has expired. Please log in again."
        }
        
    except jwt.InvalidTokenError:
        # 3. Handle tampered, malformed, or otherwise invalid tokens
        return {
            "valid": False,
            "error": "Invalid token. Authentication failed."
        }

# ==========================================
# Testing the Functions
# ==========================================
if __name__ == "__main__":
    print("--- Simulating User Login ---")
    
    # 1. Generate the token (Simulating a successful login)
    user_id = 42
    username = "alice_smith"
    
    token = generate_jwt(user_id, username)
    print(f"Generated Token:\n{token}\n")
    
    print("--- Simulating Incoming API Request ---")
    
    # 2. Verify a valid token
    result = verify_jwt(token)
    if result["valid"]:
        print("SUCCESS: Token is valid!")
        print(f"User ID from Token: {result['payload']['sub']}")
        print(f"Username from Token: {result['payload']['username']}")
    else:
        print(f"FAILED: {result['error']}")

    print("\n--- Simulating Tampered Token ---")
    
    # 3. Verify an invalid/tampered token
    # Attacker tries to change the payload or signature
    tampered_token = token[:-5] + "XXXXX" 
    
    bad_result = verify_jwt(tampered_token)
    if not bad_result["valid"]:
        print(f"REJECTED: {bad_result['error']}")