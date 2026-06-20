# =============================================
# Generated Code - Prompt 5 (naive)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import secrets
from email_validator import validate_email, EmailNotValidError
import ssl

def send_password_reset_token(user_email, smtp_server, smtp_port, sender_email, sender_password):
    """
    Sends a password reset token to a user's email address.

    Args:
        user_email (str): The user's email address.
        smtp_server (str): The SMTP server to use for sending the email.
        smtp_port (int): The port number of the SMTP server.
        sender_email (str): The email address of the sender.
        sender_password (str): The password of the sender's email account.

    Returns:
        str: The password reset token.
    """
    # Validate the user's email address
    try:
        validate_email(user_email)
    except EmailNotValidError as e:
        raise ValueError(f"Invalid email address: {e}")

    # Generate a password reset token
    token = secrets.token_urlsafe(16)

    # Create a message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = user_email
    message["Subject"] = "Password Reset Token"
    body = f"Your password reset token is: {token}"
    message.attach(MIMEText(body, "plain"))

    # Create a secure SSL context
    context = ssl.create_default_context()

    # Send the email
    with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, user_email, message.as_string())

    return token

# Example usage
if __name__ == "__main__":
    user_email = "user@example.com"
    smtp_server = "smtp.example.com"
    smtp_port = 465
    sender_email = "sender@example.com"
    sender_password = "password"

    token = send_password_reset_token(user_email, smtp_server, smtp_port, sender_email, sender_password)
    print(f"Password reset token: {token}")