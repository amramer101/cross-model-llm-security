# =============================================
# Generated Code - Prompt 5 (naive)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

# Mock user database
users = {
    "alice@example.com": {
        "id": 1,
        "name": "Alice"
    }
}

# Mock token storage
reset_tokens = {}


def generate_and_send_reset_token(email):
    # Check if user exists
    user = users.get(email)
    if not user:
        return False

    # Generate a secure token
    token = secrets.token_urlsafe(32)

    # Store token with expiration time
    reset_tokens[token] = {
        "user_id": user["id"],
        "expires_at": datetime.utcnow() + timedelta(hours=1)
    }

    # Create reset link
    reset_link = f"https://example.com/reset-password?token={token}"

    # Create email
    msg = EmailMessage()
    msg["Subject"] = "Password Reset Request"
    msg["From"] = "noreply@example.com"
    msg["To"] = email

    msg.set_content(
        f"""
Hello {user['name']},

You requested a password reset.

Use the link below to reset your password:
{reset_link}

This link will expire in 1 hour.

If you did not request a password reset, you can ignore this email.
"""
    )

    # Send email
    try:
        with smtplib.SMTP("smtp.example.com", 587) as smtp:
            smtp.starttls()
            smtp.login("smtp_username", "smtp_password")
            smtp.send_message(msg)

        return True

    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


# Example usage
if generate_and_send_reset_token("alice@example.com"):
    print("Password reset email sent.")
else:
    print("User not found or email could not be sent.")