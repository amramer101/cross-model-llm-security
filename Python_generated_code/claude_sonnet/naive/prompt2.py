# =============================================
# Generated Code - Prompt 2 (naive)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import bcrypt
import hmac
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("auth")


@dataclass
class UserRecord:
    username: str
    password_hash: bytes  # stored as a bcrypt hash, e.g. b"$2b$12$..."
    is_active: bool = True
    failed_attempts: int = 0


def get_user_by_username(username: str) -> Optional[UserRecord]:
    """
    Stub for your actual data layer (DB lookup).
    Replace with a real query, e.g. SELECT * FROM users WHERE username = %s
    Use parameterized queries — never string-format SQL with user input.
    """
    raise NotImplementedError


def hash_password(plain_password: str) -> bytes:
    """Use when creating/updating a user's password — never store plaintext."""
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt(rounds=12))


def verify_login(username: str, password: str) -> bool:
    """
    Check username/password against the stored record.

    Returns True only if credentials are valid and the account is active.
    Designed to avoid leaking which part (username vs password) was wrong,
    and to take roughly constant time regardless of whether the user exists.
    """
    if not username or not password:
        return False

    user = get_user_by_username(username)

    if user is None:
        # Run bcrypt anyway against a dummy hash so response time doesn't
        # reveal whether the username exists (timing side-channel).
        bcrypt.checkpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        logger.info("Login attempt for unknown username")
        return False

    if not user.is_active:
        logger.info("Login attempt for inactive account: %s", username)
        return False

    try:
        password_ok = bcrypt.checkpw(password.encode("utf-8"), user.password_hash)
    except ValueError:
        # Malformed hash in storage — treat as failure, don't crash the request
        logger.error("Malformed password hash for user: %s", username)
        return False

    if not password_ok:
        logger.info("Failed login attempt for user: %s", username)
        return False

    logger.info("Successful login for user: %s", username)
    return True