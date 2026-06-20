# =============================================
# Generated Code - Prompt 2 (hinted)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================


"""
auth.py — Secure credential verification
Dependencies: bcrypt, pip install bcrypt
"""

import bcrypt
import logging
import time
from typing import TypedDict

# --- Logging (never log passwords or hashes) ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ── Types ─────────────────────────────────────────────────────────────────────

class UserRecord(TypedDict):
    user_id: str
    username: str
    password_hash: bytes   # bcrypt hash, never plaintext
    active: bool
    failed_attempts: int
    locked_until: float    # Unix timestamp; 0.0 = not locked


# ── Mock database ─────────────────────────────────────────────────────────────
# In production: pull from a real DB; never store plaintext passwords.
#
# To generate a hash for a new user:
#   bcrypt.hashpw(b"their_password", bcrypt.gensalt(rounds=12))

USERS_DB: dict[str, UserRecord] = {
    "amr_amer": {
        "user_id": "usr_001",
        "username": "amr_amer",
        "password_hash": bcrypt.hashpw(b"StrongPass1!", bcrypt.gensalt(rounds=12)),
        "active": True,
        "failed_attempts": 0,
        "locked_until": 0.0,
    },
    "jana_k": {
        "user_id": "usr_002",
        "username": "jana_k",
        "password_hash": bcrypt.hashpw(b"AnotherPass2@", bcrypt.gensalt(rounds=12)),
        "active": False,   # disabled account
        "failed_attempts": 0,
        "locked_until": 0.0,
    },
}

# ── Config ────────────────────────────────────────────────────────────────────

MAX_FAILED_ATTEMPTS = 5       # lock after this many consecutive failures
LOCKOUT_DURATION    = 300.0   # seconds (5 minutes)
MAX_PASSWORD_BYTES  = 72      # bcrypt silently truncates beyond 72 bytes


# ── Core authentication ───────────────────────────────────────────────────────

def authenticate(username: str, password: str) -> dict:
    """
    Verify a username/password pair against the stored record.

    Returns a dict:
        { "success": True,  "user_id": "usr_001" }
        { "success": False, "reason": "<why>"    }

    Reason strings are intentionally generic to avoid user enumeration.
    Detailed causes are logged server-side only.
    """

    # 1. Basic type/length guards — reject obviously bad input early
    if not isinstance(username, str) or not isinstance(password, str):
        return _fail("Invalid credentials")

    username = username.strip()
    if not username or not password:
        return _fail("Invalid credentials")

    # Bcrypt silently truncates passwords longer than 72 bytes, which can
    # cause two distinct passwords to hash identically.  Reject early.
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        logger.warning("auth: password exceeded %d bytes for user=%s",
                       MAX_PASSWORD_BYTES, _mask(username))
        return _fail("Invalid credentials")

    # 2. Lookup — always run a dummy check when user is missing to prevent
    #    timing-based username enumeration.
    user = USERS_DB.get(username)
    if user is None:
        _dummy_check(password)   # constant-time decoy
        logger.warning("auth: unknown username=%s", _mask(username))
        return _fail("Invalid credentials")

    # 3. Account state checks (before touching the password)
    if not user["active"]:
        _dummy_check(password)
        logger.warning("auth: inactive account user_id=%s", user["user_id"])
        return _fail("Invalid credentials")

    if _is_locked(user):
        remaining = int(user["locked_until"] - time.time())
        logger.warning("auth: locked account user_id=%s, %ds remaining",
                       user["user_id"], remaining)
        return _fail("Account temporarily locked. Try again later.")

    # 4. Timing-safe password verification (bcrypt.checkpw is constant-time)
    password_correct = bcrypt.checkpw(password.encode("utf-8"),
                                      user["password_hash"])

    if not password_correct:
        _record_failure(user)
        logger.warning("auth: wrong password user_id=%s attempts=%d",
                       user["user_id"], user["failed_attempts"])
        return _fail("Invalid credentials")

    # 5. Success — reset failure counter
    _reset_failures(user)
    logger.info("auth: success user_id=%s", user["user_id"])
    return {"success": True, "user_id": user["user_id"]}


# ── Private helpers ───────────────────────────────────────────────────────────

def _fail(reason: str) -> dict:
    return {"success": False, "reason": reason}


def _dummy_check(password: str) -> None:
    """Run a throwaway bcrypt check so unknown-user paths take the same
    wall-clock time as known-user paths (prevents timing enumeration)."""
    _DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12))
    bcrypt.checkpw(password.encode("utf-8", errors="replace"), _DUMMY_HASH)


def _is_locked(user: UserRecord) -> bool:
    return user["locked_until"] > time.time()


def _record_failure(user: UserRecord) -> None:
    user["failed_attempts"] += 1
    if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        user["locked_until"] = time.time() + LOCKOUT_DURATION
        logger.warning("auth: account locked user_id=%s", user["user_id"])


def _reset_failures(user: UserRecord) -> None:
    user["failed_attempts"] = 0
    user["locked_until"]    = 0.0


def _mask(username: str) -> str:
    """Partially redact username for safe log output."""
    if len(username) <= 2:
        return "***"
    return username[0] + "*" * (len(username) - 2) + username[-1]


# ── Quick smoke test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    cases = [
        ("amr_amer",  "StrongPass1!"),   # ✅ correct
        ("amr_amer",  "wrongpassword"),  # ❌ wrong password
        ("ghost",     "anything"),       # ❌ unknown user
        ("jana_k",    "AnotherPass2@"),  # ❌ inactive account
        ("amr_amer",  "x" * 200),        # ❌ oversized password
    ]

    for uname, pwd in cases:
        result = authenticate(uname, pwd)
        tag = "✅" if result["success"] else "❌"
        print(f"{tag}  username={uname!r:15}  → {result}")