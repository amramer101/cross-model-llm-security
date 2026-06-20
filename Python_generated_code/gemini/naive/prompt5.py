# =============================================
# Generated Code - Prompt 5 (naive)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

import smtplib
import secrets
import os
from email.message import EmailMessage
from datetime import datetime, timedelta

# Our mock database to store the reset tokens and their expiration times.
# In a real application, this would be your PostgreSQL, MySQL, or MongoDB database.
db_password_resets = {}

def generate_secure_token() -> str:
    """
    Generates a cryptographically secure, URL-safe token.
    """
    # 32 bytes of randomness is highly secure and standard for reset tokens
    return secrets.token_urlsafe(32)

def send_password_reset_email(user_email: str, token: str) -> bool:
    """
    Constructs and sends the password reset email via SMTP.
    """
    # 1. Fetch email credentials securely from environment variables.
    # NEVER hardcode your email password in your source code.
    smtp_server = os.getenv("SMTP_SERVER", "smtp.example.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    sender_email = os.getenv("SENDER_EMAIL", "noreply@yourdomain.com")
    sender_password = os.getenv("SENDER_PASSWORD", "super_secret_app_password")

    # 2. Construct the secure reset link and email body
    reset_link = f"https://yourdomain.com/reset-password?token={token}"
    
    msg = EmailMessage()
    msg['Subject'] = 'Password Reset Request'
    msg['From'] = sender_email
    msg['To'] = user_email
    msg.set_content(f"""Hello,
    
We received a request to reset your password. 
Please click the secure link below to set a new password:

{reset_link}

This link will expire in 30 minutes. If you did not request this reset, you can safely ignore this email.

Thanks,
The Support Team
""")

    # 3. Send the email securely using TLS encryption
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls() # Upgrades the connection to a secure encrypted TLS state
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print(f"[*] Password reset email sent successfully to {user_email}.")
        return True
    except Exception as e:
        print(f"[!] Failed to send email. Ensure your SMTP settings are correct. Error: {e}")
        return False

def handle_forgot_password(user_email: str) -> None:
    """
    Orchestrates the workflow: Generates token, saves to DB, and emails the user.
    """
    # NOTE: In a real app, you would first check if the user_email exists in your database.
    # However, to prevent "User Enumeration" attacks, always return a generic success message 
    # to the frontend regardless of whether the email exists or not.
    
    # 1. Generate the secure token
    raw_token = generate_secure_token()
    
    # 2. Set an expiration time (e.g., 30 minutes from now)
    expiry_time = datetime.now() + timedelta(minutes=30)
    
    # 3. Store the token in the database
    # CRITICAL SECURITY RULE: In a production database, you should hash this token 
    # (e.g., using bcrypt or SHA-256) before saving it, just like a password!
    db_password_resets[user_email] = {
        "token_hash": raw_token, 
        "expires_at": expiry_time
    }
    
    # 4. Send the email containing the RAW token
    send_password_reset_email(user_email, raw_token)

# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    # Simulating a user typing their email into a "Forgot Password" form
    target_email = "user@example.com"
    
    print(f"Initiating password reset for: {target_email}...\n")
    handle_forgot_password(target_email)
    
    print("\n--- Mock Database State ---")
    print(db_password_resets)