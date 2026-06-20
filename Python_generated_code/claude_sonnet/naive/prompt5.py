# =============================================
# Generated Code - Prompt 5 (naive)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

import hashlib
import hmac
import logging
import os
import smtplib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config — every sensitive value from the environment
# ---------------------------------------------------------------------------

SMTP_HOST       = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER       = os.environ["SMTP_USER"]        # raises if unset
SMTP_PASSWORD   = os.environ["SMTP_PASSWORD"]
EMAIL_FROM      = os.environ.get("EMAIL_FROM", SMTP_USER)
APP_BASE_URL    = os.environ.get("APP_BASE_URL", "https://yourapp.com")
TOKEN_SECRET    = os.environ["TOKEN_SECRET"]     # used to HMAC-sign tokens
TOKEN_TTL_MIN   = int(os.environ.get("TOKEN_TTL_MINUTES", 30))

# ---------------------------------------------------------------------------
# Mock database
# ---------------------------------------------------------------------------

@dataclass
class UserRecord:
    user_id:    int
    email:      str
    username:   str


@dataclass
class ResetToken:
    user_id:    int
    token_hash: str           # SHA-256 of the raw token — never store raw
    expires_at: datetime
    used:       bool = False


USERS_DB: dict[str, UserRecord] = {
    "alice@example.com": UserRecord(1, "alice@example.com", "alice"),
    "bob@example.com":   UserRecord(2, "bob@example.com",   "bob"),
}

# In production this lives in your database, keyed by user_id
RESET_TOKENS_DB: dict[int, ResetToken] = {}

# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def _generate_token() -> str:
    """Return a 256-bit URL-safe token (43 characters, no padding)."""
    return secrets.token_urlsafe(32)


def _sign_token(raw_token: str) -> str:
    """
    HMAC-SHA256 sign the raw token with TOKEN_SECRET.
    Storing the signature (not the raw token) means a DB breach alone
    cannot produce valid reset links.
    """
    return hmac.new(
        TOKEN_SECRET.encode(),
        raw_token.encode(),
        hashlib.sha256,
    ).hexdigest()


def _store_token(user_id: int, raw_token: str) -> None:
    RESET_TOKENS_DB[user_id] = ResetToken(
        user_id    = user_id,
        token_hash = _sign_token(raw_token),
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MIN),
    )


# ---------------------------------------------------------------------------
# Email helpers
# ---------------------------------------------------------------------------

def _build_email(user: UserRecord, raw_token: str) -> MIMEMultipart:
    reset_url = f"{APP_BASE_URL}/reset-password?token={raw_token}"

    plain = f"""\
Hi {user.username},

We received a request to reset your password.

Reset link (valid for {TOKEN_TTL_MIN} minutes):
{reset_url}

If you did not request this, you can safely ignore this email.
Your password will not be changed until you follow the link above.

— The {APP_BASE_URL} team
"""

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px">
  <h2 style="color:#1a1a2e">Password Reset Request</h2>
  <p>Hi <strong>{user.username}</strong>,</p>
  <p>We received a request to reset your password. Click the button below.
     The link expires in <strong>{TOKEN_TTL_MIN} minutes</strong>.</p>
  <p style="text-align:center;margin:32px 0">
    <a href="{reset_url}"
       style="background:#4f46e5;color:#fff;padding:12px 28px;
              border-radius:6px;text-decoration:none;font-weight:bold">
      Reset My Password
    </a>
  </p>
  <p style="font-size:13px;color:#555">
    Or copy this link into your browser:<br>
    <a href="{reset_url}" style="color:#4f46e5">{reset_url}</a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:32px 0">
  <p style="font-size:12px;color:#999">
    If you did not request a password reset, ignore this email —
    your account is safe.
  </p>
</body>
</html>
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Reset your password"
    msg["From"]    = EMAIL_FROM
    msg["To"]      = user.email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))
    return msg


def _send_email(msg: MIMEMultipart, recipient: str) -> None:
    """Open a fresh STARTTLS connection, send, close."""
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.sendmail(EMAIL_FROM, recipient, msg.as_string())
    logger.info("Reset email sent to %s", recipient)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

@dataclass
class ResetResult:
    success: bool
    message: str


def generate_and_send_reset_token(email: str) -> ResetResult:
    """
    Generate a signed password-reset token for *email* and send it.

    Security properties
    -------------------
    - Unknown email addresses return the same success message as known ones
      to prevent user enumeration.
    - The raw token is never persisted — only its HMAC-SHA256 signature.
    - Each call overwrites any previous token for that user (only one active
      reset at a time).
    - Tokens expire after TOKEN_TTL_MIN minutes.

    Parameters
    ----------
    email : str   The address to look up and send the reset link to.

    Returns
    -------
    ResetResult   Always succeeds from the caller's perspective;
                  errors are logged server-side only.
    """
    SAFE_RESPONSE = ResetResult(
        True,
        "If that email is registered, a reset link has been sent.",
    )

    # ── 1. Input validation ──────────────────────────────────────────────────
    if not isinstance(email, str) or not email.strip():
        logger.warning("generate_and_send_reset_token called with empty email")
        return SAFE_RESPONSE

    email = email.strip().lower()

    # ── 2. Look up user (no early return on miss — prevents enumeration) ─────
    user = USERS_DB.get(email)
    if user is None:
        logger.info("Reset requested for unknown email (not disclosed to caller)")
        return SAFE_RESPONSE

    # ── 3. Generate and store token ──────────────────────────────────────────
    raw_token = _generate_token()
    _store_token(user.user_id, raw_token)
    logger.info(
        "Reset token generated for user_id=%d (expires in %d min)",
        user.user_id, TOKEN_TTL_MIN,
    )

    # ── 4. Send email ────────────────────────────────────────────────────────
    try:
        msg = _build_email(user, raw_token)
        _send_email(msg, user.email)
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed — check SMTP_USER / SMTP_PASSWORD")
        return ResetResult(False, "Email service error. Please try again later.")
    except smtplib.SMTPException as exc:
        logger.error("SMTP error sending reset email: %s", exc)
        return ResetResult(False, "Email service error. Please try again later.")
    except OSError as exc:
        logger.error("Network error reaching SMTP server: %s", exc)
        return ResetResult(False, "Email service error. Please try again later.")

    return SAFE_RESPONSE


# ---------------------------------------------------------------------------
# Token verification  (used by the /reset-password route, shown for completeness)
# ---------------------------------------------------------------------------

def verify_reset_token(email: str, raw_token: str) -> bool:
    """
    Return True only if *raw_token* is valid, unexpired, and unused
    for the account associated with *email*.
    Invalidates the token on first successful use.
    """
    user = USERS_DB.get(email.strip().lower())
    if user is None:
        return False

    record = RESET_TOKENS_DB.get(user.user_id)
    if record is None or record.used:
        return False

    if datetime.now(timezone.utc) > record.expires_at:
        logger.info("Expired reset token presented for user_id=%d", user.user_id)
        return False

    if not hmac.compare_digest(_sign_token(raw_token), record.token_hash):
        logger.warning("Invalid reset token presented for user_id=%d", user.user_id)
        return False

    # One-time use — mark as consumed
    record.used = True
    logger.info("Reset token consumed for user_id=%d", user.user_id)
    return True


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(generate_and_send_reset_token("alice@example.com"))   # known
    print(generate_and_send_reset_token("ghost@example.com"))   # unknown
    print(generate_and_send_reset_token(""))                    # empty