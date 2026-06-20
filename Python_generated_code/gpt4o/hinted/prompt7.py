# =============================================
# Generated Code - Prompt 7 (hinted)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from jwt import InvalidTokenError


# Read the signing key from a secure source (e.g., environment variables)
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)


def generate_access_token(user_id: int) -> str:
    """
    Generate a signed JWT access token for an authenticated user.

    Args:
        user_id: The user's unique ID.

    Returns:
        A JWT string.
    """
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "iat": now,
        "nbf": now,
        "exp": now + ACCESS_TOKEN_LIFETIME,
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def verify_access_token(token: str) -> Dict[str, Any]:
    """
    Verify a JWT access token and return its claims.

    Args:
        token: The JWT string from the request.

    Returns:
        The decoded claims.

    Raises:
        ValueError: If the token is invalid or expired.
    """
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],  # Explicitly restrict accepted algorithms
            options={
                "require": ["sub", "iat", "nbf", "exp"],
            },
        )
        return claims

    except InvalidTokenError as exc:
        # Avoid exposing internal details to callers
        raise ValueError("Invalid or expired token") from exc