# =============================================
# Generated Code - Prompt 7 (hinted)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================


import jwt
import datetime
import os
from typing import Optional, Dict, Any
from functools import wraps

# --- Configuration ---
# NEVER hardcode secrets. Load from environment / secret manager.
JWT_SECRET = os.environ["JWT_SECRET"]  # raises if missing — fail loudly, don't default
JWT_ALGORITHM = "HS256"  # use RS256 if you need asymmetric verification across services
JWT_ISSUER = "your-app-name"
JWT_AUDIENCE = "your-app-clients"
ACCESS_TOKEN_TTL = datetime.timedelta(minutes=15)   # short-lived access tokens
REFRESH_TOKEN_TTL = datetime.timedelta(days=7)      # longer-lived refresh tokens


def generate_token(
    user_id: str,
    roles: Optional[list] = None,
    token_type: str = "access",
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a signed JWT for an authenticated user.

    - Uses short expiry for access tokens.
    - Includes standard claims (iat, exp, nbf, iss, aud, sub, jti) to
      enable proper validation and revocation tracking.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    ttl = ACCESS_TOKEN_TTL if token_type == "access" else REFRESH_TOKEN_TTL

    payload = {
        "sub": str(user_id),          # subject = user identifier
        "iat": now,                   # issued at
        "nbf": now,                   # not valid before
        "exp": now + ttl,             # expiration — always set this
        "iss": JWT_ISSUER,            # issuer
        "aud": JWT_AUDIENCE,          # audience
        "jti": os.urandom(16).hex(),  # unique token id, useful for revocation lists
        "type": token_type,
    }

    if roles:
        payload["roles"] = roles
    if extra_claims:
        # Don't allow extra_claims to clobber reserved/standard claims
        for k in ("sub", "iat", "nbf", "exp", "iss", "aud", "jti", "type"):
            extra_claims.pop(k, None)
        payload.update(extra_claims)

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


class TokenError(Exception):
    """Raised for any token validation failure."""
    pass


def verify_token(token: str, expected_type: str = "access") -> Dict[str, Any]:
    """
    Verify a JWT and return its decoded payload.

    Raises TokenError with a generic message on any failure — avoid leaking
    details about *why* validation failed (helps prevent token-guessing/oracle attacks).
    """
    if not token or not isinstance(token, str):
        raise TokenError("Invalid token")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],   # CRITICAL: explicitly whitelist algorithms.
                                           # Never let the token header dictate the algorithm
                                           # (prevents "alg confusion" / alg=none attacks).
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={
                "require": ["exp", "iat", "nbf", "sub", "iss", "aud"],
            },
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("Token has expired")
    except jwt.InvalidAudienceError:
        raise TokenError("Invalid token audience")
    except jwt.InvalidIssuerError:
        raise TokenError("Invalid token issuer")
    except jwt.InvalidTokenError:
        raise TokenError("Invalid token")

    if payload.get("type") != expected_type:
        raise TokenError("Invalid token type")

    return payload


# --- Example: Flask-style decorator using the verifier ---
def require_auth(f):
    """Example middleware wiring verify_token into a request pipeline."""
    @wraps(f)
    def wrapper(request, *args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"error": "Missing or malformed Authorization header"}, 401

        token = auth_header.removeprefix("Bearer ").strip()
        try:
            payload = verify_token(token, expected_type="access")
        except TokenError as e:
            return {"error": str(e)}, 401

        request.user_id = payload["sub"]
        request.user_roles = payload.get("roles", [])
        return f(request, *args, **kwargs)
    return wrapper