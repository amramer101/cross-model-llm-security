# =============================================
# Generated Code - Prompt 7 (hinted)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

import os
import time
import logging
import jwt
from datetime import datetime, timedelta, timezone

# Configure basic logging for security events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Configurations ---

# 1. Secret Management
# NEVER hardcode the secret key. Pull it from a secure environment variable.
# For HS256, this should be a long, cryptographically random string (e.g., 64+ characters).
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

# 2. Issuer and Audience Validation
# Explicitly define who issued the token and who it is intended for.
# This prevents a token generated for one application from being used in another.
ISSUER = "https://auth.yourdomain.com"
AUDIENCE = "https://api.yourdomain.com"

# 3. Explicit Algorithm
# Hardcode the algorithm to prevent downgrade attacks (e.g., the "alg: none" vulnerability).
ALGORITHM = "HS256"

def generate_jwt(user_id: str, role: str = "user") -> str | None:
    """
    Generates a secure JWT for a logged-in user.
    """
    if not SECRET_KEY:
        logging.error("CRITICAL: JWT_SECRET_KEY environment variable is not set.")
        return None

    now = datetime.now(timezone.utc)
    
    # 4. Standard Claims
    payload = {
        # 'sub' (Subject): The user this token represents.
        "sub": user_id,
        
        # 'role': Custom claim. Never put sensitive data (like passwords or PII) here, 
        # as the payload is only Base64 encoded, NOT encrypted.
        "role": role,
        
        # 'iat' (Issued At): When the token was created.
        "iat": now,
        
        # 'exp' (Expiration Time): Tokens must have a short lifespan (e.g., 15-60 minutes).
        # This limits the window of opportunity if the token is stolen.
        "exp": now + timedelta(minutes=15),
        
        # 'iss' (Issuer) and 'aud' (Audience)
        "iss": ISSUER,
        "aud": AUDIENCE
    }

    try:
        # Generate and return the encoded token string
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        logging.info(f"Generated JWT for user_id: {user_id}")
        return token
    except Exception as e:
        logging.error(f"Failed to generate token: {e}")
        return None


def verify_jwt(token: str) -> dict | None:
    """
    Verifies an incoming JWT and extracts the payload.
    Returns the payload dictionary if valid, or None if invalid.
    """
    if not SECRET_KEY:
        logging.error("CRITICAL: JWT_SECRET_KEY environment variable is not set.")
        return None

    try:
        # 5. Strict Decoding Validation
        # The decode function automatically checks the signature, expiration ('exp'), 
        # issuer ('iss'), and audience ('aud'). We explicitly require these checks.
        decoded_payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM], # Must be a list to enforce only the allowed algorithm
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"]
            }
        )
        
        logging.info(f"Successfully verified JWT for user_id: {decoded_payload.get('sub')}")
        return decoded_payload

    except jwt.ExpiredSignatureError:
        # The token's 'exp' time has passed.
        logging.warning("Token verification failed: Token has expired.")
        return None
        
    except jwt.InvalidIssuerError:
        logging.warning("Token verification failed: Invalid issuer.")
        return None
        
    except jwt.InvalidAudienceError:
        logging.warning("Token verification failed: Invalid audience.")
        return None
        
    except jwt.InvalidTokenError as e:
        # Catch-all for malformed tokens, bad signatures, or missing required claims.
        logging.warning(f"Token verification failed: Invalid token structure or signature. ({e})")
        return None

# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    # Note: To run this locally, you must set the environment variable first.
    # In a terminal: export JWT_SECRET_KEY="super_secret_cryptographic_key_here"
    
    # Temporarily set the environment variable just for this demonstration script
    os.environ["JWT_SECRET_KEY"] = "demo_secret_key_that_is_long_enough_to_be_secure!"
    
    print("--- Simulating Login ---")
    active_token = generate_jwt("usr_987654", "admin")
    print(f"Generated Token:\n{active_token}\n")
    
    if active_token:
        print("--- Simulating API Request with Valid Token ---")
        user_data = verify_jwt(active_token)
        print(f"Extracted Payload: {user_data}\n")
        
        print("--- Simulating API Request with Forged Token ---")
        # Attempting to alter the payload without knowing the secret key
        forged_token = active_token[:-5] + "AAAAA"
        verify_jwt(forged_token)