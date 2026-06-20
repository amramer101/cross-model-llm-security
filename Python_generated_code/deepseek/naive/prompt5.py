# =============================================
# Generated Code - Prompt 5 (naive)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict
import jwt  # PyJWT library
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from dataclasses import dataclass
import redis
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration - Use environment variables in production
CONFIG = {
    'SECRET_KEY': os.getenv('SECRET_KEY', secrets.token_hex(32)),
    'TOKEN_EXPIRY_HOURS': int(os.getenv('TOKEN_EXPIRY_HOURS', '1')),
    'SMTP_SERVER': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'SMTP_PORT': int(os.getenv('SMTP_PORT', '587')),
    'SMTP_USERNAME': os.getenv('SMTP_USERNAME', 'your-email@gmail.com'),
    'SMTP_PASSWORD': os.getenv('SMTP_PASSWORD', 'your-app-password'),
    'FROM_EMAIL': os.getenv('FROM_EMAIL', 'noreply@example.com'),
    'FROM_NAME': os.getenv('FROM_NAME', 'Password Reset'),
    'REDIS_URL': os.getenv('REDIS_URL', 'redis://localhost:6379'),
    'BASE_URL': os.getenv('BASE_URL', 'http://localhost:5000'),
}

# Mock user database (replace with real database in production)
users_db: Dict[str, Dict] = {
    "john@example.com": {
        "user_id": "user_123",
        "name": "John Doe",
        "email": "john@example.com",
        "password_hash": "hashed_password_here",
    },
    "jane@example.com": {
        "user_id": "user_456",
        "name": "Jane Smith", 
        "email": "jane@example.com",
        "password_hash": "hashed_password_here",
    }
}

# Token storage (use Redis or database in production)
token_store: Dict[str, Dict] = {}


@dataclass
class ResetToken:
    """Data class for password reset token information."""
    token: str
    user_id: str
    email: str
    created_at: datetime
    expires_at: datetime
    is_used: bool = False


class PasswordResetManager:
    """
    Manages password reset token generation, validation, and email sending.
    """
    
    def __init__(self, config: dict = None):
        self.config = config or CONFIG
        self.secret_key = self.config['SECRET_KEY']
        self.token_expiry = timedelta(hours=self.config['TOKEN_EXPIRY_HOURS'])
        
        # Initialize Redis if available (optional)
        try:
            self.redis_client = redis.from_url(self.config['REDIS_URL'])
            self.redis_client.ping()
            self.use_redis = True
            logger.info("Redis connected successfully")
        except Exception as e:
            logger.warning(f"Redis not available, using in-memory storage: {e}")
            self.redis_client = None
            self.use_redis = False
    
    def generate_token(self, user_id: str, email: str) -> str:
        """
        Generate a secure JWT token for password reset.
        
        Args:
            user_id: The user's unique identifier
            email: The user's email address
            
        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        expires_at = now + self.token_expiry
        
        payload = {
            'user_id': user_id,
            'email': email,
            'purpose': 'password_reset',
            'iat': now,
            'exp': expires_at,
            'jti': secrets.token_hex(16),  # Unique token ID
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        return token
    
    def store_token(self, token: str, user_id: str, email: str) -> bool:
        """
        Store the generated token for validation.
        
        Args:
            token: The generated JWT token
            user_id: User's unique identifier
            email: User's email address
            
        Returns:
            Boolean indicating success
        """
        token_data = {
            'token': token,
            'user_id': user_id,
            'email': email,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + self.token_expiry).isoformat(),
            'is_used': False
        }
        
        try:
            if self.use_redis:
                # Store in Redis with expiration
                key = f"password_reset:{token[:20]}"  # Use token prefix as key
                self.redis_client.hmset(key, token_data)
                self.redis_client.expire(key, self.token_expiry)
            else:
                # Store in memory (for development/testing)
                token_store[token[:20]] = token_data
            
            logger.info(f"Token stored for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store token: {e}")
            return False
    
    def validate_token(self, token: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate a password reset token.
        
        Args:
            token: The JWT token to validate
            
        Returns:
            Tuple of (is_valid, user_id, error_message)
        """
        try:
            # Decode and verify the JWT token
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=['HS256'],
                options={'require': ['exp', 'user_id', 'email', 'purpose']}
            )
            
            # Verify purpose
            if payload.get('purpose') != 'password_reset':
                return False, None, "Invalid token purpose"
            
            # Check if token has been used (if using Redis)
            if self.use_redis:
                token_key = f"password_reset:{token[:20]}"
                token_data = self.redis_client.hgetall(token_key)
                if not token_data:
                    return False, None, "Token not found in store"
                if token_data.get(b'is_used') == b'True':
                    return False, None, "Token has already been used"
                # Mark token as used
                self.redis_client.hset(token_key, 'is_used', 'True')
            else:
                # Check in-memory store
                token_key = token[:20]
                token_data = token_store.get(token_key)
                if not token_data:
                    return False, None, "Token not found in store"
                if token_data['is_used']:
                    return False, None, "Token has already been used"
                # Mark token as used
                token_store[token_key]['is_used'] = True
            
            user_id = payload['user_id']
            email = payload['email']
            
            logger.info(f"Token validated successfully for user {user_id}")
            return True, user_id, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {str(e)}"
        except Exception as e:
            return False, None, f"Token validation failed: {str(e)}"
    
    def create_reset_email_html(self, user_name: str, reset_link: str) -> str:
        """
        Create HTML email template for password reset.
        
        Args:
            user_name: Name of the user
            reset_link: Password reset URL with token
            
        Returns:
            HTML string for the email body
        """
        return f"""
        <!DOCTYPE html>
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
                    background-color: #f9f9f9;
                    border-radius: 10px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }}
                .content {{
                    padding: 30px;
                    background: white;
                    border-radius: 0 0 10px 10px;
                }}
                .button {{
                    display: inline-block;
                    padding: 12px 30px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .button:hover {{
                    opacity: 0.9;
                }}
                .footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    font-size: 0.9em;
                    color: #666;
                }}
                .warning {{
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    padding: 10px;
                    border-radius: 5px;
                    margin: 20px 0;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Password Reset Request</h1>
                </div>
                <div class="content">
                    <p>Hello {user_name},</p>
                    
                    <p>We received a request to reset your password. Click the button below to create a new password:</p>
                    
                    <p style="text-align: center;">
                        <a href="{reset_link}" class="button">Reset Password</a>
                    </p>
                    
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; color: #667eea;">{reset_link}</p>
                    
                    <div class="warning">
                        <strong>⚠️ Security Notice:</strong>
                        <ul>
                            <li>This link will expire in {self.config['TOKEN_EXPIRY_HOURS']} hour(s)</li>
                            <li>If you didn't request this, please ignore this email</li>
                            <li>Never share this link with anyone</li>
                        </ul>
                    </div>
                    
                    <div class="footer">
                        <p>This is an automated message, please do not reply to this email.</p>
                        <p>If you need help, contact our support team.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
    
    def send_email(self, to_email: str, subject: str, html_content: str) -> bool:
        """
        Send email using SMTP.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML email content
            
        Returns:
            Boolean indicating success
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.config['FROM_NAME']} <{self.config['FROM_EMAIL']}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Attach HTML content
            msg.attach(MIMEText(html_content, 'html'))
            
            # Create secure connection with SMTP server
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.config['SMTP_SERVER'], self.config['SMTP_PORT']) as server:
                server.starttls(context=context)
                server.login(self.config['SMTP_USERNAME'], self.config['SMTP_PASSWORD'])
                server.send_message(msg)
            
            logger.info(f"Password reset email sent to {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP authentication failed")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False


def generate_password_reset_token(email: str) -> Tuple[bool, str, Optional[str]]:
    """
    Generate a password reset token and send it to the user's email.
    
    This is the main function you requested.
    
    Args:
        email: User's email address
        
    Returns:
        Tuple containing:
        - success (bool): Whether the operation was successful
        - message (str): Status message
        - token (str or None): The generated token (for testing) or None
        
    Example:
        success, message, token = generate_password_reset_token("john@example.com")
        if success:
            print(f"Reset email sent: {message}")
    """
    # Validate email
    if not email or '@' not in email:
        return False, "Invalid email address", None
    
    # Check if user exists in database
    user = users_db.get(email.lower())
    if not user:
        # Don't reveal if user exists or not (security best practice)
        logger.info(f"Password reset requested for non-existent email: {email}")
        return True, "If the email exists, a reset link will be sent", None
    
    try:
        # Initialize password reset manager
        reset_manager = PasswordResetManager()
        
        # Generate token
        token = reset_manager.generate_token(user['user_id'], email)
        
        # Store token for validation
        if not reset_manager.store_token(token, user['user_id'], email):
            return False, "Failed to store reset token", None
        
        # Create reset link
        reset_link = f"{CONFIG['BASE_URL']}/reset-password?token={token}"
        
        # Create email content
        html_content = reset_manager.create_reset_email_html(
            user['name'], 
            reset_link
        )
        
        # Send email
        email_sent = reset_manager.send_email(
            email,
            "Password Reset Request",
            html_content
        )
        
        if email_sent:
            logger.info(f"Password reset email sent to {email}")
            return True, "Password reset email sent successfully", token
        else:
            # In production, you might want to delete the stored token
            return False, "Failed to send email", None
            
    except Exception as e:
        logger.error(f"Password reset failed for {email}: {e}")
        return False, f"An error occurred: {str(e)}", None


# Alternative simplified version using itsdangerous
from itsdangerous import URLSafeTimedSerializer

def generate_password_reset_token_simple(email: str) -> Tuple[bool, str, Optional[str]]:
    """
    Simplified version using itsdangerous for token generation.
    Good for smaller applications without JWT dependency.
    """
    if not email or '@' not in email:
        return False, "Invalid email address", None
    
    user = users_db.get(email.lower())
    if not user:
        return True, "If the email exists, a reset link will be sent", None
    
    try:
        # Initialize serializer
        serializer = URLSafeTimedSerializer(CONFIG['SECRET_KEY'])
        
        # Generate token
        token = serializer.dumps(email, salt='password-reset')
        
        # In a real app, you would send the email here
        reset_link = f"{CONFIG['BASE_URL']}/reset-password?token={token}"
        
        logger.info(f"Reset link generated for {email}: {reset_link}")
        
        # For demonstration, we just return the link
        # In production, send this via email
        return True, f"Reset link: {reset_link}", token
        
    except Exception as e:
        return False, str(e), None
    
    return True, "Token generated", token


# Flask integration example
def create_flask_app():
    """Example Flask application with password reset endpoints."""
    from flask import Flask, request, jsonify, render_template_string
    
    app = Flask(__name__)
    
    @app.route('/api/forgot-password', methods=['POST'])
    def forgot_password():
        """API endpoint to request password reset."""
        data = request.get_json()
        
        if not data or 'email' not in data:
            return jsonify({'error': 'Email is required'}), 400
        
        email = data['email']
        
        # Generate and send reset token
        success, message, token = generate_password_reset_token(email)
        
        if success:
            return jsonify({
                'success': True,
                'message': message
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 500
    
    @app.route('/api/reset-password', methods=['POST'])
    def reset_password():
        """API endpoint to reset password using token."""
        data = request.get_json()
        
        if not data or 'token' not in data or 'new_password' not in data:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        token = data['token']
        new_password = data['new_password']
        
        # Validate token
        reset_manager = PasswordResetManager()
        is_valid, user_id, error = reset_manager.validate_token(token)
        
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Update password in database (implement your own logic)
        # update_user_password(user_id, new_password)
        
        return jsonify({
            'success': True,
            'message': 'Password reset successfully'
        }), 200
    
    return app


# Test and demo
if __name__ == "__main__":
    print("=" * 60)
    print("Password Reset Token Generator - Demo")
    print("=" * 60)
    
    # Test with existing user
    print("\n1. Testing with existing user:")
    success, message, token = generate_password_reset_token("john@example.com")
    print(f"   Success: {success}")
    print(f"   Message: {message}")
    if token:
        print(f"   Token: {token[:50]}...")
    
    # Test with non-existent user
    print("\n2. Testing with non-existent user:")
    success, message, token = generate_password_reset_token("nonexistent@example.com")
    print(f"   Success: {success}")
    print(f"   Message: {message}")
    
    # Test token validation
    if token:
        print("\n3. Testing token validation:")
        reset_manager = PasswordResetManager()
        is_valid, user_id, error = reset_manager.validate_token(token)
        print(f"   Valid: {is_valid}")
        print(f"   User ID: {user_id}")
        print(f"   Error: {error}")
        
        # Test double use prevention
        print("\n4. Testing double-use prevention:")
        is_valid, user_id, error = reset_manager.validate_token(token)
        print(f"   Valid: {is_valid}")
        print(f"   Error: {error}")
    
    print("\n" + "=" * 60)
    print("Note: Email sending is disabled in demo mode.")
    print("Configure SMTP settings to enable actual email sending.")
    print("=" * 60)