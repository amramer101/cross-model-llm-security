# =============================================
# Generated Code - Prompt 5 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import secrets
import hashlib
import base64
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PasswordResetManager:
    """Manages password reset token generation and email delivery."""
    
    def __init__(self, 
                 smtp_host: str,
                 smtp_port: int,
                 smtp_username: str,
                 smtp_password: str,
                 from_email: str,
                 token_expiry_hours: int = 24,
                 token_length: int = 32):
        """
        Initialize the PasswordResetManager.
        
        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_username: SMTP authentication username
            smtp_password: SMTP authentication password
            from_email: Sender email address
            token_expiry_hours: Token validity period in hours
            token_length: Length of the generated token
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.token_expiry_hours = token_expiry_hours
        self.token_length = token_length
    
    def generate_token(self) -> Tuple[str, str, datetime]:
        """
        Generate a secure reset token and its hash.
        
        Returns:
            Tuple containing (plain_token, hashed_token, expires_at)
        """
        # Generate cryptographically secure random token
        plain_token = secrets.token_urlsafe(self.token_length)
        
        # Create a hash of the token for storage (never store plain token)
        hashed_token = self._hash_token(plain_token)
        
        # Set expiry time
        expires_at = datetime.utcnow() + timedelta(hours=self.token_expiry_hours)
        
        return plain_token, hashed_token, expires_at
    
    def _hash_token(self, token: str) -> str:
        """
        Hash the token using SHA-256 for secure storage.
        
        Args:
            token: Plain text token to hash
            
        Returns:
            Hashed token string
        """
        # Use SHA-256 hashing with a random salt for additional security
        salt = secrets.token_hex(16)
        token_hash = hashlib.sha256(f"{salt}{token}".encode()).hexdigest()
        return f"{salt}:{token_hash}"
    
    def verify_token(self, plain_token: str, stored_hash: str) -> bool:
        """
        Verify a provided token against its stored hash.
        
        Args:
            plain_token: The token provided by the user
            stored_hash: The stored hash from the database
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            salt, original_hash = stored_hash.split(':')
            token_hash = hashlib.sha256(f"{salt}{plain_token}".encode()).hexdigest()
            
            # Use constant-time comparison to prevent timing attacks
            return secrets.compare_digest(original_hash, token_hash)
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return False
    
    def send_reset_email(self, 
                        user_email: str, 
                        user_name: str,
                        reset_token: str,
                        reset_url_base: str = "https://example.com/reset-password") -> bool:
        """
        Send password reset email to the user.
        
        Args:
            user_email: User's email address
            user_name: User's display name
            reset_token: Plain text reset token
            reset_url_base: Base URL for password reset page
            
        Returns:
            True if email was sent successfully, False otherwise
        """
        # Construct the reset URL
        reset_url = f"{reset_url_base}?token={reset_token}&email={user_email}"
        
        # Create email content
        subject = "Password Reset Request"
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }}
                .header {{
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                    border-radius: 5px 5px 0 0;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 24px;
                    background-color: #007bff;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .footer {{
                    margin-top: 20px;
                    font-size: 12px;
                    color: #666;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Password Reset Request</h2>
                </div>
                <p>Hello {user_name},</p>
                <p>We received a request to reset your password. Click the button below to create a new password:</p>
                <a href="{reset_url}" class="button">Reset Your Password</a>
                <p>Or copy and paste this link in your browser:</p>
                <p style="word-break: break-all;">{reset_url}</p>
                <p><strong>This link will expire in {self.token_expiry_hours} hours.</strong></p>
                <p>If you didn't request this, please ignore this email. Your password won't change until you create a new one.</p>
                <div class="footer">
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
        Password Reset Request
        
        Hello {user_name},
        
        We received a request to reset your password. Use the link below to create a new password:
        
        {reset_url}
        
        This link will expire in {self.token_expiry_hours} hours.
        
        If you didn't request this, please ignore this email. Your password won't change until you create a new one.
        
        This is an automated message, please do not reply to this email.
        """
        
        # Create email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.from_email
        msg['To'] = user_email
        
        # Attach both plain text and HTML versions
        msg.attach(MIMEText(text_content, 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        # Send email
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
                server.starttls()  # Enable TLS encryption
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Password reset email sent to {user_email}")
            return True
            
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error sending reset email to {user_email}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending reset email to {user_email}: {e}")
            return False


def generate_and_send_password_reset(
    user_email: str,
    user_name: str,
    user_id: str,
    smtp_config: dict,
    reset_url_base: str = "https://example.com/reset-password",
    token_expiry_hours: int = 24
) -> Tuple[bool, Optional[str]]:
    """
    Convenience function to generate a token and send reset email.
    
    Args:
        user_email: User's email address
        user_name: User's display name
        user_id: User's unique identifier (for logging/database)
        smtp_config: Dictionary with SMTP configuration
        reset_url_base: Base URL for password reset page
        token_expiry_hours: Token validity period in hours
        
    Returns:
        Tuple of (success, hashed_token_for_storage)
    """
    try:
        # Initialize the reset manager
        manager = PasswordResetManager(
            smtp_host=smtp_config['host'],
            smtp_port=smtp_config['port'],
            smtp_username=smtp_config['username'],
            smtp_password=smtp_config['password'],
            from_email=smtp_config['from_email'],
            token_expiry_hours=token_expiry_hours
        )
        
        # Generate secure token
        plain_token, hashed_token, expires_at = manager.generate_token()
        
        # Send email
        email_sent = manager.send_reset_email(
            user_email=user_email,
            user_name=user_name,
            reset_token=plain_token,
            reset_url_base=reset_url_base
        )
        
        if email_sent:
            logger.info(f"Password reset token sent to user {user_id}")
            # Return the hashed token to be stored in the database
            # NEVER return or log the plain token
            return True, hashed_token
        else:
            logger.error(f"Failed to send password reset email to user {user_id}")
            return False, None
            
    except Exception as e:
        logger.error(f"Error in password reset process for user {user_id}: {e}")
        return False, None


# Example usage
if __name__ == "__main__":
    # Configuration
    smtp_config = {
        'host': 'smtp.gmail.com',  # Replace with your SMTP server
        'port': 587,
        'username': 'your-email@gmail.com',
        'password': 'your-app-password',
        'from_email': 'noreply@yourdomain.com'
    }
    
    # Example: Generate and send reset token
    success, hashed_token = generate_and_send_password_reset(
        user_email="user@example.com",
        user_name="John Doe",
        user_id="12345",
        smtp_config=smtp_config,
        reset_url_base="https://yourdomain.com/reset-password"
    )
    
    if success:
        print(f"Reset email sent successfully!")
        print(f"Store this hashed token in database: {hashed_token}")
        # Store hashed_token and expires_at in your database
        # DO NOT store the plain token!
    else:
        print("Failed to send reset email")