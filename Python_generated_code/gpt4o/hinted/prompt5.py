# =============================================
# Generated Code - Prompt 5 (hinted)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import secrets
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from hashlib import sha256


def generate_and_send_password_reset(
    user_id: int,
    email_address: str,
    save_reset_token_hash,
) -> None:
    """
    Generates a one-time password reset token, stores only its hash,
    and emails the token to the user.

    Args:
        user_id: User's unique ID.
        email_address: User's email address.
        save_reset_token_hash: Callable that persists the token hash
                               and expiration time for the user.
                               Signature:
                               save_reset_token_hash(user_id, token_hash, expires_at)
    """
    # Generate a cryptographically secure random token
    token = secrets.token_urlsafe(32)

    # Store only a hash of the token
    token_hash = sha256(token.encode("utf-8")).hexdigest()

    # Set an expiration time (e.g. 1 hour)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    # Persist the token hash and expiration in your database
    save_reset_token_hash(user_id, token_hash, expires_at)

    # Construct a reset URL
    reset_url = f"https://example.com/reset-password?token={token}"

    # Create the email
    message = EmailMessage()
    message["Subject"] = "Password Reset Request"
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = email_address
    message.set_content(
        f"""A password reset was requested for your account.

Use the link below to reset your password:

{reset_url}

This link expires in 1 hour.

If you did not request a password reset, you can safely ignore this email.
"""
    )

    # Send the email securely
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(
        os.environ["SMTP_HOST"],
        int(os.environ.get("SMTP_PORT", "465")),
        context=context,
    ) as smtp:
        smtp.login(
            os.environ["SMTP_USERNAME"],
            os.environ["SMTP_PASSWORD"],
        )
        smtp.send_message(message)