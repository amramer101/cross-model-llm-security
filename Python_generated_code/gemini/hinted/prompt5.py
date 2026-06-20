# =============================================
# Generated Code - Prompt 5 (hinted)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import secrets
import hashlib
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Mock database simulating user records and token storage
MOCK_USER_DB = {
    "alice@example.com": {
        "user_id": 1,
        "reset_token_hash": None,
        "token_expires_at": None
    }
}

def generate_and_store_token(email: str) -> str | None:
    """
    Generates a cryptographically secure token, hashes it for storage, 
    and sets a strict expiration time.
    """
    user_record = MOCK_USER_DB.get(email)
    
    # 1. Anti-Enumeration
    # If the user doesn't exist, we return None but handle it silently downstream
    # so attackers cannot use the password reset form to guess valid emails.
    if not user_record:
        logging.info(f"Password reset requested for non-existent email: {email}")
        return None

    # 2. Cryptographically Secure Generation
    # Generates a 32-byte URL-safe string. Do not use random.choice() or UUIDs, 
    # as they are not cryptographically secure and can be predicted.
    raw_token = secrets.token_urlsafe(32)

    # 3. Secure Storage (Hashing)
    # We hash the token before storing it. If the DB is leaked, the tokens are useless.
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    
    # 4. Strict Expiration
    # Tokens should have a very short lifespan (e.g., 15 minutes).
    expiration_time = datetime.now(timezone.utc) + timedelta(minutes=15)

    # Update the mock database
    MOCK_USER_DB[email]["reset_token_hash"] = token_hash
    MOCK_USER_DB[email]["token_expires_at"] = expiration_time
    
    logging.info(f"Generated secure reset token for {email}")
    
    # Return the raw token ONLY this one time so it can be emailed.
    return raw_token

def send_reset_email(recipient_email: str, raw_token: str) -> bool:
    """
    Constructs and sends the password reset email securely over TLS.
    """
    # 5. Secret Management
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.example.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASSWORD")

    if not all([smtp_user, smtp_pass]):
        logging.error("SMTP credentials missing from environment variables.")
        return False

    # 6. Secure Link Construction
    # Ensure your application uses HTTPS in production.
    reset_link = f"https://yourdomain.com/reset-password?token={raw_token}&email={recipient_email}"

    # Construct the email
    msg = EmailMessage()
    msg['Subject'] = 'Password Reset Request'
    msg['From'] = "security@yourdomain.com"
    msg['To'] = recipient_email
    msg.set_content(
        f"Hello,\n\n"
        f"You requested a password reset. Click the link below to set a new password:\n"
        f"{reset_link}\n\n"
        f"This link will expire in 15 minutes. If you did not request this, please ignore this email.\n"
    )

    try:
        # 7. Secure Transmission (STARTTLS)
        # Upgrades the connection to an encrypted TLS payload before sending credentials.
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls() 
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
            
        logging.info(f"Password reset email successfully sent to {recipient_email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        return False

def initiate_password_reset(email: str) -> None:
    """
    The main orchestration function called by your web endpoint.
    """
    # Generate the token (returns None if user doesn't exist)
    raw_token = generate_and_store_token(email)
    
    if raw_token:
        # Send the email only if a valid token was generated
        send_reset_email(email, raw_token)
    
    # 8. Opaque Responses
    # Always return a generic success message to the client regardless of 
    # whether the email existed or not.
    print(f"Server Response: 'If {email} exists in our system, a reset link has been sent.'")

# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    # Note: To run the email portion locally, you must set SMTP environment variables.
    
    print("--- Simulating Password Reset for Existing User ---")
    initiate_password_reset("alice@example.com")
    
    print("\n--- Simulating Password Reset for Non-Existent User ---")
    initiate_password_reset("ghost@example.com")