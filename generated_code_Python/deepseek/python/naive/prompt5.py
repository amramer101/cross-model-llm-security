# =============================================
# Generated Code - Prompt 5 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import secrets
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import os

# Mock user database
users_db = {
    "john@example.com": {
        "id": 1,
        "username": "john_doe",
        "password_hash": "hashed_password_here",
        "reset_token": None,
        "reset_token_expiry": None
    },
    "jane@example.com": {
        "id": 2,
        "username": "jane_smith",
        "password_hash": "hashed_password_here",
        "reset_token": None,
        "reset_token_expiry": None
    }
}

def generate_reset_token_simple(email: str) -> Tuple[bool, str]:
    """
    Generate a password reset token and send it via email.
    
    Args:
        email (str): User's email address
        
    Returns:
        Tuple[bool, str]: Success status and message
    """
    # Check if user exists
    if email not in users_db:
        # Return success anyway to prevent email enumeration
        return True, "If the email exists, a reset link has been sent"
    
    # Generate secure token
    token = secrets.token_urlsafe(32)
    
    # Set token and expiry (1 hour from now)
    users_db[email]['reset_token'] = token
    users_db[email]['reset_token_expiry'] = datetime.now() + timedelta(hours=1)
    
    # Create reset link
    reset_link = f"https://yourdomain.com/reset-password?token={token}"
    
    # Email configuration
    sender_email = os.getenv('SMTP_EMAIL', 'noreply@yourdomain.com')
    sender_password = os.getenv('SMTP_PASSWORD', 'your-password')
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    
    # Create email message
    subject = "Password Reset Request"
    body = f"""
    Hello {users_db[email]['username']},
    
    We received a request to reset your password. Click the link below to reset it:
    
    {reset_link}
    
    This link will expire in 1 hour.
    
    If you didn't request this, please ignore this email.
    
    Best regards,
    Your Application Team
    """
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        # Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        return True, "If the email exists, a reset link has been sent"
    
    except Exception as e:
        # Clear token if email fails
        users_db[email]['reset_token'] = None
        users_db[email]['reset_token_expiry'] = None
        return False, f"Failed to send email: {str(e)}"