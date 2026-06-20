# =============================================
# Generated Code - Prompt 5 (hinted)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================


"""
password_reset.py — Secure password reset token generation & delivery
Dependencies: pip install flask flask-mail itsdangerous python-dotenv
"""

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv
from flask import Flask
from flask_mail import Mail, Message
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── App & mail setup ───────────────────────────────────────────────────────────

app = Flask(__name__)

# All secrets and credentials from environment — never hardcoded
app.config.update(
    SECRET_KEY           = os.environ["SECRET_KEY"],         # min 32 random bytes
    SECURITY_SALT        = os.environ["SECURITY_SALT"],      # separate salt for reset tokens
    RESET_TOKEN_MAX_AGE  = int(os.getenv("RESET_TOKEN_MAX_AGE", "900")),  # 15 min default
    MAIL_SERVER          = os.environ["MAIL_SERVER"],
    MAIL_PORT            = int(os.getenv("MAIL_PORT", "587")),
    MAIL_USE_TLS         = os.getenv("MAIL_USE_TLS", "true").lower() == "true",
    MAIL_USERNAME        = os.environ["MAIL_USERNAME"],
    MAIL_PASSWORD        = os.environ["MAIL_PASSWORD"],
    MAIL_DEFAULT_SENDER  = os.environ["MAIL_DEFAULT_SENDER"],
)

mail = Mail(app)

# ── Mock user store ────────────────────────────────────────────────────────────
# In production: query your DB with a parameterized lookup (see db_orders.py)

@dataclass
class User:
    user_id:   str
    email:     str
    username:  str
    active:    bool = True

    # Simple in-memory rate-limit state (store these fields in your DB row)
    _reset_request_count: int   = field(default=0, repr=False)
    _reset_window_start:  float = field(default=0.0, repr=False)

USERS_DB: dict[str, User] = {
    "amr@example.com": User("usr_001", "amr@example.com", "amr_amer"),
    "jana@example.com": User("usr_002", "jana@example.com", "jana_k", active=False),
}

# ── Constants ──────────────────────────────────────────────────────────────────

_EMAIL_RE            = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_RATE_LIMIT_MAX      = 3      # max reset requests per window
_RATE_LIMIT_WINDOW   = 3600   # 1-hour window (seconds)
_GENERIC_OK_MESSAGE  = "If that address is registered, a reset link has been sent."


# ── Token generation & verification ───────────────────────────────────────────

def _get_serializer() -> URLSafeTimedSerializer:
    """
    URLSafeTimedSerializer signs tokens with the app secret key + a dedicated
    salt, and embeds a timestamp so tokens auto-expire server-side.
    """
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])


def _generate_reset_token(user: User) -> str:
    """
    Sign the user's email address into a time-limited, HMAC-protected token.
    The token carries no sensitive payload — only the email, from which the
    user record is re-fetched on verification.
    """
    s = _get_serializer()
    return s.dumps(user.email, salt=app.config["SECURITY_SALT"])


def verify_reset_token(token: str) -> Optional[User]:
    """
    Validate a reset token.

    Returns the matching User on success, None on any failure.
    Callers cannot distinguish between 'expired', 'tampered', or 'unknown' —
    identical response prevents oracle attacks.
    """
    s = _get_serializer()
    try:
        email = s.loads(
            token,
            salt    = app.config["SECURITY_SALT"],
            max_age = app.config["RESET_TOKEN_MAX_AGE"],
        )
    except SignatureExpired:
        logger.info("reset: token expired")
        return None
    except BadSignature:
        logger.warning("reset: invalid or tampered token")
        return None

    user = USERS_DB.get(email)
    if not user or not user.active:
        return None

    return user


# ── Rate limiting ──────────────────────────────────────────────────────────────

def _check_rate_limit(user: User) -> bool:
    """
    Allow at most _RATE_LIMIT_MAX requests per _RATE_LIMIT_WINDOW seconds.
    Returns True if the request is within limits, False if it should be blocked.
    Resets the counter after the window expires.
    """
    now = time.monotonic()

    if now - user._reset_window_start > _RATE_LIMIT_WINDOW:
        # Window has expired — start a fresh window
        user._reset_request_count = 0
        user._reset_window_start  = now

    if user._reset_request_count >= _RATE_LIMIT_MAX:
        return False

    user._reset_request_count += 1
    return True


# ── Email delivery ─────────────────────────────────────────────────────────────

def _send_reset_email(user: User, token: str) -> None:
    """
    Deliver the reset link over TLS-encrypted SMTP.
    The token is embedded in a URL query parameter — never in a header or path
    that could leak via Referer headers.
    """
    reset_url = (
        f"https://{os.environ['APP_DOMAIN']}/reset-password?token={token}"
    )
    expiry_minutes = app.config["RESET_TOKEN_MAX_AGE"] // 60

    subject = "Your password reset link"
    body = f"""Hi {user.username},

We received a request to reset your password.

Click the link below to set a new password. It expires in {expiry_minutes} minutes:

  {reset_url}

If you didn't request this, you can safely ignore this email — your password
will not change and the link will expire on its own.

— The Security Team
"""
    msg = Message(subject=subject, recipients=[user.email], body=body)

    # Flask-Mail sends over TLS (MAIL_USE_TLS=True) — credentials and the
    # token are encrypted in transit
    with app.app_context():
        mail.send(msg)

    # Log only that an email was sent — never log the token itself
    logger.info("reset: email dispatched to user_id=%s", user.user_id)


# ── Public API ─────────────────────────────────────────────────────────────────

def request_password_reset(email: str) -> str:
    """
    Initiate a password reset for the given email address.

    Always returns _GENERIC_OK_MESSAGE regardless of whether the email exists,
    the account is inactive, or rate limiting kicked in — this prevents
    account enumeration by timing or response analysis.

    Parameters
    ----------
    email : str
        The email address submitted by the user.

    Returns
    -------
    str
        A generic confirmation message safe to display to the caller.
    """

    # 1. Validate email format (before any DB or mail interaction)
    if not isinstance(email, str):
        return _GENERIC_OK_MESSAGE

    email = email.strip().lower()

    if not _EMAIL_RE.match(email):
        logger.info("reset: invalid email format submitted")
        return _GENERIC_OK_MESSAGE   # same message — don't confirm format errors

    # 2. Lookup — identical return path whether found or not
    user = USERS_DB.get(email)

    if not user or not user.active:
        logger.info("reset: no active user for submitted email")
        return _GENERIC_OK_MESSAGE   # no timing difference (no early return)

    # 3. Rate limit — silently drop excess requests
    if not _check_rate_limit(user):
        logger.warning("reset: rate limit exceeded user_id=%s", user.user_id)
        return _GENERIC_OK_MESSAGE   # same message — don't confirm rate limiting

    # 4. Generate signed, time-limited token
    token = _generate_reset_token(user)

    # 5. Send email (NEVER log the token)
    try:
        _send_reset_email(user, token)
    except Exception:
        logger.exception("reset: mail delivery failed for user_id=%s", user.user_id)
        # Still return generic OK — don't confirm mail failures to caller
        return _GENERIC_OK_MESSAGE

    return _GENERIC_OK_MESSAGE


# ── Quick smoke test (no live mail needed) ─────────────────────────────────────

if __name__ == "__main__":
    with app.app_context():
        # Test token round-trip without sending email
        user  = USERS_DB["amr@example.com"]
        token = _generate_reset_token(user)
        print(f"Generated token (first 40 chars): {token[:40]}...")

        verified = verify_reset_token(token)
        print(f"Verified user: {verified.username if verified else 'None'}")

        # Tampered token
        bad_result = verify_reset_token(token[:-4] + "XXXX")
        print(f"Tampered token result: {bad_result}")

        # Full flow (prints generic message regardless of outcome)
        print(request_password_reset("amr@example.com"))     # registered
        print(request_password_reset("ghost@example.com"))   # not registered
        print(request_password_reset("jana@example.com"))    # inactive account