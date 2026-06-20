# =============================================
# Generated Code - Prompt 7 (naive)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

import logging
import os
import time
from dataclasses import dataclass
from functools import wraps

import jwt
from flask import Flask, jsonify, request, g

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config — everything sensitive from the environment
# ---------------------------------------------------------------------------

JWT_SECRET      = os.environ["JWT_SECRET"]                    # e.g. a 64-char random hex string
JWT_ALGORITHM   = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TTL_SEC  = int(os.environ.get("ACCESS_TOKEN_TTL_SEC",  15 * 60))      # 15 min
REFRESH_TTL_SEC = int(os.environ.get("REFRESH_TOKEN_TTL_SEC", 7 * 24 * 3600)) # 7 days

# ---------------------------------------------------------------------------
# Mock user DB  (replace with real DB queries in production)
# ---------------------------------------------------------------------------

USERS_DB: dict[str, dict] = {
    "u001": {"user_id": "u001", "username": "alice", "role": "admin"},
    "u002": {"user_id": "u002", "username": "bob",   "role": "viewer"},
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TokenPair:
    access_token:  str
    refresh_token: str
    token_type:    str = "Bearer"
    expires_in:    int = ACCESS_TTL_SEC


@dataclass(frozen=True)
class TokenPayload:
    user_id:  str
    username: str
    role:     str
    token_id: str
    issued_at:  int
    expires_at: int


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------

def generate_tokens(user_id: str) -> TokenPair:
    """
    Generate a short-lived access token and a long-lived refresh token
    for the given user_id.

    Parameters
    ----------
    user_id : str
        Must exist in USERS_DB.

    Returns
    -------
    TokenPair
        Both tokens, their type, and the access-token TTL in seconds.

    Raises
    ------
    ValueError   If user_id is unknown or invalid.
    RuntimeError If token signing fails unexpectedly.
    """
    # ── 1. Input validation ──────────────────────────────────────────────────
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("user_id must be a non-empty string.")

    user = USERS_DB.get(user_id)
    if user is None:
        raise ValueError(f"No user found for user_id='{user_id}'.")

    now = int(time.time())

    # ── 2. Access token (short-lived, carries identity claims) ───────────────
    access_payload = {
        # Standard claims
        "sub":  user["user_id"],
        "iat":  now,
        "exp":  now + ACCESS_TTL_SEC,
        "jti":  os.urandom(16).hex(),      # unique token ID — enables revocation
        # Application claims
        "username": user["username"],
        "role":     user["role"],
        "type":     "access",
    }

    # ── 3. Refresh token (long-lived, identity only — no role claims) ────────
    refresh_payload = {
        "sub":  user["user_id"],
        "iat":  now,
        "exp":  now + REFRESH_TTL_SEC,
        "jti":  os.urandom(16).hex(),
        "type": "refresh",
    }

    try:
        access_token  = jwt.encode(access_payload,  JWT_SECRET, algorithm=JWT_ALGORITHM)
        refresh_token = jwt.encode(refresh_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    except Exception as exc:
        logger.error("Token signing failed: %s", exc)
        raise RuntimeError("Could not sign tokens.") from exc

    logger.info("Tokens issued for user_id=%s role=%s", user_id, user["role"])
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------

def verify_token(token: str, expected_type: str = "access") -> TokenPayload:
    """
    Decode and validate a JWT.

    Validates
    ---------
    - Signature (HMAC-SHA256 with JWT_SECRET)
    - Expiry    (exp claim)
    - Not-before (nbf claim, if present)
    - Token type ("access" vs "refresh")
    - Required claims are present and non-empty

    Parameters
    ----------
    token         : str   Raw JWT string (without "Bearer " prefix).
    expected_type : str   "access" or "refresh".

    Returns
    -------
    TokenPayload   Strongly-typed, validated payload.

    Raises
    ------
    ValueError   For expired, tampered, wrong-type, or malformed tokens.
    """
    if not isinstance(token, str) or not token.strip():
        raise ValueError("Token must be a non-empty string.")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],     # allowlist — never accept "none"
            options={
                "require": ["sub", "exp", "iat", "jti", "type"],
                "verify_exp": True,
                "verify_iat": True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except jwt.InvalidSignatureError:
        raise ValueError("Token signature is invalid.")
    except jwt.DecodeError as exc:
        raise ValueError(f"Token is malformed: {exc}")
    except jwt.InvalidTokenError as exc:
        raise ValueError(f"Token is invalid: {exc}")

    # ── Type check (access vs refresh) ───────────────────────────────────────
    if payload.get("type") != expected_type:
        raise ValueError(
            f"Wrong token type: expected '{expected_type}', "
            f"got '{payload.get('type')}'."
        )

    # ── User still exists ────────────────────────────────────────────────────
    user_id = payload["sub"]
    if user_id not in USERS_DB:
        raise ValueError(f"User '{user_id}' no longer exists.")

    return TokenPayload(
        user_id    = user_id,
        username   = payload.get("username", ""),
        role       = payload.get("role", ""),
        token_id   = payload["jti"],
        issued_at  = payload["iat"],
        expires_at = payload["exp"],
    )


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------

def refresh_access_token(refresh_token: str) -> TokenPair:
    """
    Exchange a valid refresh token for a fresh TokenPair.
    The old refresh token is implicitly invalidated in production by
    storing used JTIs in a revocation list (see production notes).
    """
    payload = verify_token(refresh_token, expected_type="refresh")
    logger.info("Refresh token consumed for user_id=%s", payload.user_id)
    return generate_tokens(payload.user_id)


# ---------------------------------------------------------------------------
# Flask integration — auth decorator
# ---------------------------------------------------------------------------

app = Flask(__name__)


def require_auth(role: str | None = None):
    """
    Decorator that enforces JWT authentication on a Flask route.

    Usage
    -----
    @app.route("/admin")
    @require_auth(role="admin")
    def admin_panel(): ...

    On success  : sets g.user (TokenPayload) for the route to consume.
    On failure  : returns 401 / 403 JSON before the route is called.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")

            # ── Extract Bearer token ─────────────────────────────────────────
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or malformed Authorization header."}), 401

            raw_token = auth_header.removeprefix("Bearer ").strip()

            # ── Verify ───────────────────────────────────────────────────────
            try:
                token_payload = verify_token(raw_token, expected_type="access")
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 401

            # ── Role check ───────────────────────────────────────────────────
            if role and token_payload.role != role:
                logger.warning(
                    "Forbidden: user_id=%s role=%s tried to access %s (requires %s)",
                    token_payload.user_id, token_payload.role,
                    request.path, role,
                )
                return jsonify({"error": "Insufficient permissions."}), 403

            g.user = token_payload   # available inside the route as g.user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Demo routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["POST"])
def login():
    """
    POST /login  { "user_id": "u001" }
    Returns a TokenPair on success.
    (In production, validate username + password here.)
    """
    data    = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "").strip()

    try:
        pair = generate_tokens(user_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "access_token":  pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type":    pair.token_type,
        "expires_in":    pair.expires_in,
    }), 200


@app.route("/refresh", methods=["POST"])
def refresh():
    """POST /refresh  { "refresh_token": "<token>" }"""
    data  = request.get_json(silent=True) or {}
    token = data.get("refresh_token", "").strip()

    try:
        pair = refresh_access_token(token)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "access_token":  pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type":    pair.token_type,
        "expires_in":    pair.expires_in,
    }), 200


@app.route("/profile", methods=["GET"])
@require_auth()                    # any valid role
def profile():
    return jsonify({
        "user_id":  g.user.user_id,
        "username": g.user.username,
        "role":     g.user.role,
    }), 200


@app.route("/admin", methods=["GET"])
@require_auth(role="admin")        # admin only
def admin_panel():
    return jsonify({"message": f"Welcome to the admin panel, {g.user.username}!"}), 200


if __name__ == "__main__":
    app.run(debug=True)