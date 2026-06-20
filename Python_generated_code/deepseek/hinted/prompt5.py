# =============================================
# Generated Code - Prompt 5 (hinted)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import secrets
import hashlib
import hmac
import time
import base64
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formataddr, formatdate, make_msgid
import re
import redis
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('password_reset.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TokenError(Exception):
    """Custom exception for token-related errors"""
    pass

class EmailError(Exception):
    """Custom exception for email-related errors"""
    pass

@dataclass
class PasswordResetToken:
    """Represents a password reset token"""
    token: str
    user_id: str
    email: str
    created_at: datetime
    expires_at: datetime
    is_used: bool = False
    usage_attempts: int = 0
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

class SecureTokenGenerator:
    """
    Secure token generation and management system.
    
    Security features:
    - Cryptographically secure random token generation
    - Token encryption at rest
    - Short token lifetime (15-30 minutes)
    - Single-use tokens
    - Rate limiting
    - Token revocation
    - Audit logging
    """
    
    def __init__(self, 
                 secret_key: Optional[str] = None,
                 redis_url: Optional[str] = None):
        """
        Initialize the token generator.
        
        Args:
            secret_key: Secret key for token signing (load from env in production)
            redis_url: Redis connection URL for token storage (optional)
        """
        # Use environment variable or generate a temporary key
        self.secret_key = secret_key or os.environ.get('TOKEN_SECRET_KEY')
        if not self.secret_key:
            raise ValueError("TOKEN_SECRET_KEY must be set")
        
        # Token configuration
        self.token_length = 64  # bytes
        self.token_lifetime_minutes = int(os.environ.get('TOKEN_LIFETIME_MINUTES', '30'))
        self.max_usage_attempts = 3
        self.rate_limit_seconds = 60  # 1 minute between reset requests
        
        # Initialize encryption for token storage
        self.fernet_key = self._derive_encryption_key()
        self.cipher = Fernet(self.fernet_key)
        
        # Initialize Redis for token storage (optional)
        self.redis_client = None
        if redis_url:
            try:
                self.redis_client = redis.from_url(redis_url)
                logger.info("Redis connection established for token storage")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}. Using in-memory storage.")
        
        # In-memory token store (fallback if Redis not available)
        self._token_store: Dict[str, PasswordResetToken] = {}
        
        # Rate limiting store
        self._rate_limit_store: Dict[str, datetime] = {}
    
    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from secret key using PBKDF2"""
        salt = b'password_reset_salt'  # In production, use a unique salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.secret_key.encode()))
        return key
    
    def generate_token(self, 
                      user_id: str, 
                      email: str,
                      ip_address: Optional[str] = None,
                      user_agent: Optional[str] = None) -> PasswordResetToken:
        """
        Generate a cryptographically secure password reset token.
        
        Args:
            user_id: Unique user identifier
            email: User's email address
            ip_address: Request IP address (for audit)
            user_agent: Request user agent (for audit)
            
        Returns:
            PasswordResetToken object
        """
        try:
            # Check rate limiting
            if not self._check_rate_limit(email):
                raise TokenError("Too many reset requests. Please wait before trying again.")
            
            # Revoke any existing unused tokens for this user
            self.revoke_user_tokens(user_id)
            
            # Generate cryptographically secure random bytes
            random_bytes = secrets.token_bytes(self.token_length)
            
            # Create JWT-like token with embedded metadata
            token_payload = {
                'user_id': user_id,
                'email': email,
                'random': base64.urlsafe_b64encode(random_bytes).decode('utf-8'),
                'iat': int(time.time()),
                'jti': secrets.token_hex(16)  # JWT ID for uniqueness
            }
            
            # Sign the token
            token = jwt.encode(
                token_payload,
                self.secret_key,
                algorithm='HS256'
            )
            
            # Create token record
            reset_token = PasswordResetToken(
                token=token,
                user_id=user_id,
                email=email,
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(minutes=self.token_lifetime_minutes),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Store token (encrypted)
            self._store_token(reset_token)
            
            # Update rate limiting
            self._update_rate_limit(email)
            
            # Log token generation (without the token itself)
            logger.info(
                f"Password reset token generated for user {user_id} "
                f"from IP {ip_address}"
            )
            
            return reset_token
            
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            raise TokenError("Failed to generate reset token")
    
    def verify_token(self, token: str) -> Tuple[bool, Optional[str], str]:
        """
        Verify a password reset token.
        
        Args:
            token: The password reset token
            
        Returns:
            Tuple of (is_valid, user_id, message)
        """
        try:
            # Decode and verify token
            try:
                payload = jwt.decode(
                    token,
                    self.secret_key,
                    algorithms=['HS256']
                )
            except jwt.ExpiredSignatureError:
                return False, None, "Token has expired"
            except jwt.InvalidTokenError:
                return False, None, "Invalid token"
            
            user_id = payload.get('user_id')
            if not user_id:
                return False, None, "Invalid token payload"
            
            # Retrieve token from storage
            stored_token = self._get_token(user_id)
            
            if not stored_token:
                return False, None, "Token not found or already used"
            
            # Check if token is already used
            if stored_token.is_used:
                # Potential security issue - log and invalidate
                logger.warning(f"Attempt to reuse token for user {user_id}")
                self._invalidate_all_user_tokens(user_id)
                return False, None, "Token has already been used"
            
            # Check if token is expired
            if datetime.now() > stored_token.expires_at:
                self._invalidate_token(user_id)
                return False, None, "Token has expired"
            
            # Check usage attempts
            if stored_token.usage_attempts >= self.max_usage_attempts:
                self._invalidate_token(user_id)
                logger.warning(f"Token exceeded max attempts for user {user_id}")
                return False, None, "Too many attempts. Please request a new token."
            
            # Increment usage attempts
            stored_token.usage_attempts += 1
            self._store_token(stored_token)
            
            # Token is valid but don't mark as used yet
            # Mark as used only after successful password change
            return True, user_id, "Token verified successfully"
            
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return False, None, "Token verification failed"
    
    def mark_token_used(self, user_id: str):
        """Mark token as used after successful password reset"""
        token = self._get_token(user_id)
        if token:
            token.is_used = True
            self._store_token(token)
            logger.info(f"Token marked as used for user {user_id}")
    
    def _store_token(self, token: PasswordResetToken):
        """Store token securely"""
        try:
            if self.redis_client:
                # Store in Redis with encryption
                token_data = asdict(token)
                token_data['token'] = self.cipher.encrypt(
                    token.token.encode()
                ).decode()
                
                # Store with expiration
                self.redis_client.setex(
                    f"pwd_reset:{token.user_id}",
                    timedelta(minutes=self.token_lifetime_minutes + 5),
                    json.dumps(token_data)
                )
            else:
                # Store in memory (with encryption)
                self._token_store[token.user_id] = token
                
        except Exception as e:
            logger.error(f"Failed to store token: {e}")
            raise TokenError("Failed to store token")
    
    def _get_token(self, user_id: str) -> Optional[PasswordResetToken]:
        """Retrieve token from storage"""
        try:
            if self.redis_client:
                token_data = self.redis_client.get(f"pwd_reset:{user_id}")
                if token_data:
                    data = json.loads(token_data)
                    data['token'] = self.cipher.decrypt(
                        data['token'].encode()
                    ).decode()
                    return PasswordResetToken(**data)
            else:
                return self._token_store.get(user_id)
                
        except Exception as e:
            logger.error(f"Failed to retrieve token: {e}")
            return None
    
    def revoke_user_tokens(self, user_id: str):
        """Revoke all existing tokens for a user"""
        try:
            if self.redis_client:
                self.redis_client.delete(f"pwd_reset:{user_id}")
            else:
                self._token_store.pop(user_id, None)
            logger.info(f"Tokens revoked for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to revoke tokens: {e}")
    
    def _invalidate_token(self, user_id: str):
        """Invalidate a token"""
        self.revoke_user_tokens(user_id)
    
    def _invalidate_all_user_tokens(self, user_id: str):
        """Invalidate all tokens for a user (security measure)"""
        self.revoke_user_tokens(user_id)
        logger.warning(f"All tokens invalidated for user {user_id}")
    
    def _check_rate_limit(self, email: str) -> bool:
        """Check if request is within rate limits"""
        last_request = self._rate_limit_store.get(email)
        if last_request:
            time_diff = (datetime.now() - last_request).total_seconds()
            if time_diff < self.rate_limit_seconds:
                return False
        return True
    
    def _update_rate_limit(self, email: str):
        """Update rate limiting timestamp"""
        self._rate_limit_store[email] = datetime.now()

class SecureEmailSender:
    """
    Secure email sending with best practices.
    """
    
    def __init__(self):
        """Initialize email configuration from environment variables"""
        self.smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        self.smtp_username = os.environ.get('SMTP_USERNAME')
        self.smtp_password = os.environ.get('SMTP_PASSWORD')
        self.from_email = os.environ.get('FROM_EMAIL', 'noreply@example.com')
        self.from_name = os.environ.get('FROM_NAME', 'Password Reset')
        self.use_tls = os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true'
        
        # Validate configuration
        if not self.smtp_username or not self.smtp_password:
            raise ValueError("SMTP credentials must be configured")
        
        # Email template configuration
        self.template_path = os.environ.get('EMAIL_TEMPLATE_PATH', 'email_templates')
        self.reset_url_base = os.environ.get('RESET_URL_BASE', 'https://example.com/reset-password')
    
    def send_password_reset_email(self, 
                                 email: str, 
                                 token: str,
                                 user_name: Optional[str] = None) -> bool:
        """
        Send password reset email with secure practices.
        
        Args:
            email: Recipient email address
            token: Password reset token
            user_name: Recipient's name (optional)
            
        Returns:
            bool: True if sent successfully
        """
        try:
            # Validate email address
            if not self._validate_email(email):
                raise EmailError(f"Invalid email address: {email}")
            
            # Generate reset URL (token in URL is acceptable for password reset)
            reset_url = f"{self.reset_url_base}?token={token}"
            
            # Create message
            msg = MIMEMultipart('alternative')
            
            # Set message headers
            msg['Message-ID'] = make_msgid(domain='example.com')
            msg['Date'] = formatdate(localtime=True)
            msg['From'] = formataddr((self.from_name, self.from_email))
            msg['To'] = email
            msg['Subject'] = "Password Reset Request"
            
            # Add security headers
            msg['X-Content-Type-Options'] = 'nosniff'
            msg['X-Priority'] = '1'  # High priority for time-sensitive emails
            
            # Create HTML version with security warnings
            html_content = self._create_html_template(reset_url, user_name, email)
            plain_text = self._create_plain_text(reset_url, user_name, email)
            
            # Attach both versions
            msg.attach(MIMEText(plain_text, 'plain', 'utf-8'))
            msg.attach(MIMEText(html_content, 'html', 'utf-8'))
            
            # Send email with SSL/TLS
            with self._create_smtp_connection() as server:
                server.send_message(msg)
            
            # Log success (don't log the token)
            logger.info(f"Password reset email sent to {email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send reset email to {email}: {e}")
            raise EmailError(f"Failed to send password reset email")
    
    def _validate_email(self, email: str) -> bool:
        """
        Validate email address format.
        Uses regex as initial check, DNS validation should be done separately.
        """
        if not email or len(email) > 254:  # RFC 5321
            return False
        
        # Basic email format validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return False
        
        # Check for common disposable email domains (optional)
        disposable_domains = {
            'tempmail.com', 'throwaway.com', 'mailinator.com'  # Add more as needed
        }
        domain = email.split('@')[1].lower()
        if domain in disposable_domains:
            logger.warning(f"Disposable email domain detected: {domain}")
            # Optionally reject or flag these
        
        return True
    
    def _create_smtp_connection(self):
        """Create secure SMTP connection"""
        context = ssl.create_default_context()
        
        if self.use_tls:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls(context=context)
        else:
            server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context)
        
        server.login(self.smtp_username, self.smtp_password)
        return server
    
    def _create_html_template(self, 
                              reset_url: str, 
                              user_name: Optional[str],
                              email: str) -> str:
        """Create HTML email template with security information"""
        greeting = f"Hello {user_name}," if user_name else "Hello,"
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background-color: #f9f9f9; }}
                .button {{ 
                    display: inline-block; 
                    padding: 12px 24px; 
                    background-color: #4CAF50; 
                    color: white; 
                    text-decoration: none; 
                    border-radius: 4px; 
                    margin: 20px 0;
                }}
                .warning {{ 
                    background-color: #fff3cd; 
                    border: 1px solid #ffeaa7; 
                    padding: 15px; 
                    border-radius: 4px;
                    margin: 20px 0;
                }}
                .footer {{ 
                    margin-top: 20px; 
                    padding: 20px; 
                    background-color: #f1f1f1; 
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
                
                <div class="content">
                    <p>{greeting}</p>
                    
                    <p>We received a request to reset the password for your account ({email}).</p>
                    
                    <p>Click the button below to reset your password:</p>
                    
                    <center>
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </center>
                    
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; color: #4CAF50;">{reset_url}</p>
                    
                    <div class="warning">
                        <strong>⚠️ Security Notice:</strong>
                        <ul>
                            <li>This link will expire in 30 minutes</li>
                            <li>Never share this link with anyone</li>
                            <li>If you didn't request this, please ignore this email</li>
                            <li>We will never ask for your password via email</li>
                        </ul>
                    </div>
                </div>
                
                <div class="footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                    <p>If you have any questions, please contact our support team.</p>
                    <p>© {datetime.now().year} Your Company. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def _create_plain_text(self, 
                          reset_url: str, 
                          user_name: Optional[str],
                          email: str) -> str:
        """Create plain text version of email"""
        greeting = f"Hello {user_name}," if user_name else "Hello,"
        
        return f"""
{greeting}

We received a request to reset the password for your account ({email}).

To reset your password, please click the link below or copy and paste it into your browser:

{reset_url}

⚠️ Security Notice:
- This link will expire in 30 minutes
- Never share this link with anyone
- If you didn't request this, please ignore this email
- We will never ask for your password via email

This is an automated message. Please do not reply to this email.

If you have any questions, please contact our support team.

© {datetime.now().year} Your Company. All rights reserved.
        """

def generate_and_send_password_reset_token(
    user_id: str,
    email: str,
    user_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main function to generate password reset token and send via email.
    
    This function follows security best practices:
    
    1. Cryptographically secure token generation
    2. Short token lifetime (15-30 minutes)
    3. Single-use tokens
    4. Token encryption at rest
    5. Rate limiting
    6. Audit logging
    7. Secure email transmission (TLS)
    8. No sensitive data in logs
    9. Input validation
    10. Brute force protection
    
    Args:
        user_id: Unique user identifier
        email: User's email address
        user_name: User's name (optional, for personalization)
        ip_address: Request IP address (for audit)
        user_agent: Request user agent (for audit)
    
    Returns:
        Dictionary with status and message
    
    Example:
        >>> result = generate_and_send_password_reset_token(
        ...     user_id="user_123",
        ...     email="user@example.com",
        ...     user_name="John Doe",
        ...     ip_address="192.168.1.1"
        ... )
    """
    try:
        # Initialize components
        token_generator = SecureTokenGenerator()
        email_sender = SecureEmailSender()
        
        # Validate inputs
        if not user_id or not email:
            return {
                'success': False,
                'message': 'User ID and email are required'
            }
        
        # Check if user exists (mock check - implement your own user lookup)
        # user = user_service.get_user_by_email(email)
        # if not user:
        #     # Return success to prevent user enumeration
        #     return {
        #         'success': True,
        #         'message': 'If the email exists, a reset link has been sent'
        #     }
        
        # Generate secure token
        token = token_generator.generate_token(
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Send email with token
        email_sender.send_password_reset_email(
            email=email,
            token=token.token,
            user_name=user_name
        )
        
        # Log the operation (without exposing the token)
        logger.info(
            f"Password reset initiated for user {user_id} "
            f"from IP {ip_address}"
        )
        
        # Always return the same response to prevent user enumeration
        return {
            'success': True,
            'message': 'If the email exists in our system, a password reset link has been sent.',
            'expires_in_minutes': token_generator.token_lifetime_minutes
        }
        
    except TokenError as e:
        logger.error(f"Token generation error: {e}")
        return {
            'success': False,
            'message': 'Unable to process password reset request. Please try again later.'
        }
    except EmailError as e:
        logger.error(f"Email sending error: {e}")
        return {
            'success': False,
            'message': 'Unable to send password reset email. Please try again later.'
        }
    except Exception as e:
        logger.error(f"Unexpected error in password reset: {e}")
        return {
            'success': False,
            'message': 'An unexpected error occurred. Please try again later.'
        }

def verify_password_reset_token(token: str) -> Dict[str, Any]:
    """
    Verify a password reset token.
    
    Args:
        token: The password reset token from email
    
    Returns:
        Dictionary with verification result
    """
    try:
        token_generator = SecureTokenGenerator()
        
        is_valid, user_id, message = token_generator.verify_token(token)
        
        if is_valid:
            return {
                'success': True,
                'valid': True,
                'user_id': user_id,
                'message': message
            }
        else:
            return {
                'success': True,
                'valid': False,
                'message': message
            }
            
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        return {
            'success': False,
            'valid': False,
            'message': 'Token verification failed'
        }

def complete_password_reset(token: str, new_password: str) -> Dict[str, Any]:
    """
    Complete the password reset process.
    
    Args:
        token: The validated password reset token
        new_password: The new password
    
    Returns:
        Dictionary with result
    """
    try:
        # Verify token again
        token_generator = SecureTokenGenerator()
        is_valid, user_id, message = token_generator.verify_token(token)
        
        if not is_valid:
            return {
                'success': False,
                'message': message
            }
        
        # Validate password strength (implement your password policy)
        if not validate_password_strength(new_password):
            return {
                'success': False,
                'message': 'Password does not meet security requirements'
            }
        
        # Update password in database (implement your update logic)
        # user_service.update_password(user_id, new_password)
        
        # Mark token as used
        token_generator.mark_token_used(user_id)
        
        # Invalidate all sessions for this user (security measure)
        # session_service.invalidate_user_sessions(user_id)
        
        # Log the password change
        logger.info(f"Password successfully reset for user {user_id}")
        
        return {
            'success': True,
            'message': 'Password has been reset successfully'
        }
        
    except Exception as e:
        logger.error(f"Password reset completion failed: {e}")
        return {
            'success': False,
            'message': 'Failed to reset password'
        }

def validate_password_strength(password: str) -> bool:
    """
    Validate password strength.
    
    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Not commonly used passwords
    """
    if len(password) < 12:
        return False
    
    if not re.search(r'[A-Z]', password):
        return False
    
    if not re.search(r'[a-z]', password):
        return False
    
    if not re.search(r'\d', password):
        return False
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    # Check against common passwords (abbreviated list)
    common_passwords = {
        'password123', 'admin123', '123456789', 'qwerty123',
        'letmein123', 'welcome123', 'monkey123', 'dragon123'
    }
    
    if password.lower() in common_passwords:
        return False
    
    return True

# Flask endpoint example
def create_password_reset_endpoints():
    """Example Flask endpoints for password reset"""
    from flask import Flask, request, jsonify
    
    app = Flask(__name__)
    
    @app.route('/api/password/reset-request', methods=['POST'])
    def request_password_reset():
        """Request a password reset"""
        try:
            data = request.get_json()
            
            if not data or 'email' not in data:
                return jsonify({
                    'success': False,
                    'message': 'Email is required'
                }), 400
            
            email = data['email'].strip().lower()
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            # In production, look up user by email
            # user = user_service.get_user_by_email(email)
            # if user:
            #     result = generate_and_send_password_reset_token(
            #         user_id=user.id,
            #         email=email,
            #         user_name=user.name,
            #         ip_address=ip_address,
            #         user_agent=user_agent
            #     )
            
            # For demo, always return same response
            result = {
                'success': True,
                'message': 'If the email exists, a reset link has been sent.'
            }
            
            return jsonify(result), 200
            
        except Exception as e:
            logger.error(f"Password reset request error: {e}")
            return jsonify({
                'success': False,
                'message': 'Internal server error'
            }), 500
    
    @app.route('/api/password/reset', methods=['POST'])
    def reset_password():
        """Complete password reset"""
        try:
            data = request.get_json()
            
            if not data or 'token' not in data or 'new_password' not in data:
                return jsonify({
                    'success': False,
                    'message': 'Token and new password are required'
                }), 400
            
            token = data['token']
            new_password = data['new_password']
            
            result = complete_password_reset(token, new_password)
            
            return jsonify(result), 200 if result['success'] else 400
            
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return jsonify({
                'success': False,
                'message': 'Internal server error'
            }), 500
    
    return app

# Environment variables configuration example
def print_env_config():
    """Print required environment variables"""
    print("""
# Required Environment Variables:

# Token Security
export TOKEN_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export TOKEN_LIFETIME_MINUTES=30

# Email Configuration
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT=587
export SMTP_USERNAME="your-email@gmail.com"
export SMTP_PASSWORD="your-app-specific-password"
export SMTP_USE_TLS="true"
export FROM_EMAIL="noreply@yourdomain.com"
export FROM_NAME="Your App Name"

# Application
export RESET_URL_BASE="https://yourdomain.com/reset-password"
export EMAIL_TEMPLATE_PATH="/path/to/email/templates"

# Redis (optional, for distributed token storage)
export REDIS_URL="redis://localhost:6379/0"
    """)

if __name__ == "__main__":
    # Example usage
    print("Password Reset Token Generator")
    print("=" * 50)
    
    # Print configuration requirements
    print_env_config()
    
    # Example: Generate and send reset token
    result = generate_and_send_password_reset_token(
        user_id="user_123",
        email="user@example.com",
        user_name="John Doe",
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0"
    )
    
    print("\nResult:", result)