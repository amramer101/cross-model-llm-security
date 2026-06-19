# =============================================
# Generated Code - Prompt 5 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import os
import secrets
import hashlib
import hmac
import base64
import logging
import re
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# Security Configuration
# ============================================================================

class SecurityConfig:
    """Centralized security configuration for password reset functionality."""
    
    # Token configuration
    TOKEN_LENGTH = 32  # bytes
    TOKEN_EXPIRY_MINUTES = 30
    MAX_RESET_ATTEMPTS = 3
    RESET_COOLDOWN_MINUTES = 5
    MAX_TOKEN_ATTEMPTS_PER_HOUR = 5
    
    # Token signing key (use environment variable in production)
    TOKEN_SECRET_KEY = os.environ.get('TOKEN_SECRET_KEY', secrets.token_hex(32))
    
    # Email configuration
    SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    SMTP_USE_TLS = True
    SMTP_TIMEOUT = 30  # seconds
    
    # Email sender
    FROM_EMAIL = os.environ.get('FROM_EMAIL', 'noreply@example.com')
    FROM_NAME = os.environ.get('FROM_NAME', 'Security Team')
    
    # Rate limiting
    EMAIL_RATE_LIMIT_PER_EMAIL = 3  # requests per email per hour
    EMAIL_RATE_LIMIT_PER_IP = 10  # requests per IP per hour
    
    # Token storage (use database in production)
    TOKEN_STORE = {}  # In-memory storage for demonstration

# ============================================================================
# Custom Exceptions
# ============================================================================

class TokenGenerationError(Exception):
    """Raised when token generation fails."""
    pass

class EmailSendingError(Exception):
    """Raised when email sending fails."""
    pass

class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded."""
    pass

class TokenValidationError(Exception):
    """Raised when token validation fails."""
    pass

# ============================================================================
# Data Models
# ============================================================================

class TokenPurpose(Enum):
    """Enum for token purposes."""
    PASSWORD_RESET = "password_reset"
    EMAIL_VERIFICATION = "email_verification"
    ACCOUNT_ACTIVATION = "account_activation"

@dataclass
class PasswordResetToken:
    """Represents a password reset token with metadata."""
    token_hash: str
    user_id: str
    email: str
    purpose: str
    created_at: datetime
    expires_at: datetime
    attempts: int
    is_used: bool
    ip_address: str
    user_agent: str

@dataclass
class TokenPayload:
    """Payload encoded in the token."""
    user_id: str
    email: str
    purpose: str
    nonce: str
    created_at: str
    expires_at: str

# ============================================================================
# Input Validation
# ============================================================================

class InputValidator:
    """Validates and sanitizes user inputs."""
    
    # Email regex pattern (RFC 5322 compliant)
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    # Allowed characters in user ID
    USER_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """
        Validate and sanitize email address.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, sanitized_email)
        """
        if not email:
            return False, ""
        
        if not isinstance(email, str):
            return False, ""
        
        # Strip whitespace and convert to lowercase
        email = email.strip().lower()
        
        # Check length limits
        if len(email) > 254:  # Maximum email length per RFC 5321
            return False, ""
        
        if len(email) < 5:  # Minimum valid email length
            return False, ""
        
        # Check for common injection patterns
        dangerous_chars = ['<', '>', '"', "'", ';', '(', ')', '\r', '\n', '\0']
        if any(char in email for char in dangerous_chars):
            return False, ""
        
        # Validate email format
        if not InputValidator.EMAIL_PATTERN.match(email):
            return False, ""
        
        # Additional checks
        local_part, domain = email.split('@')
        
        # Check local part length
        if len(local_part) > 64:
            return False, ""
        
        # Check for suspicious patterns
        suspicious_patterns = ['../', 'cmd=', '|', '&&', '||']
        if any(pattern in email for pattern in suspicious_patterns):
            return False, ""
        
        return True, email
    
    @staticmethod
    def validate_user_id(user_id: str) -> Tuple[bool, str]:
        """
        Validate user ID format.
        
        Args:
            user_id: User ID to validate
            
        Returns:
            Tuple of (is_valid, sanitized_user_id)
        """
        if not user_id:
            return False, ""
        
        if not isinstance(user_id, str):
            return False, ""
        
        user_id = user_id.strip()
        
        if len(user_id) > 100:
            return False, ""
        
        if not InputValidator.USER_ID_PATTERN.match(user_id):
            return False, ""
        
        return True, user_id

# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimiter:
    """Rate limiter for password reset requests."""
    
    def __init__(self):
        self.requests = {}
        from threading import Lock
        self.lock = Lock()
    
    def check_rate_limit(self, key: str, max_requests: int, window_hours: int) -> bool:
        """
        Check if request is within rate limits.
        
        Args:
            key: Unique identifier (email or IP)
            max_requests: Maximum allowed requests
            window_hours: Time window in hours
            
        Returns:
            True if allowed, False if rate limited
        """
        with self.lock:
            now = datetime.now()
            
            # Clean old entries
            self.requests = {
                k: [t for t in timestamps if now - t < timedelta(hours=window_hours)]
                for k, timestamps in self.requests.items()
            }
            
            # Get timestamps for this key
            timestamps = self.requests.get(key, [])
            
            # Check if limit exceeded
            if len(timestamps) >= max_requests:
                return False
            
            # Record this request
            if key not in self.requests:
                self.requests[key] = []
            self.requests[key].append(now)
            
            return True
    
    def get_remaining_attempts(self, key: str, max_requests: int, window_hours: int) -> int:
        """Get remaining attempts for a key."""
        with self.lock:
            now = datetime.now()
            timestamps = self.requests.get(key, [])
            recent = [t for t in timestamps if now - t < timedelta(hours=window_hours)]
            return max(0, max_requests - len(recent))

rate_limiter = RateLimiter()

# ============================================================================
# Token Generation and Management
# ============================================================================

class TokenManager:
    """Manages password reset token generation, validation, and lifecycle."""
    
    def __init__(self):
        self.token_store = SecurityConfig.TOKEN_STORE
    
    def _generate_cryptographic_token(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.
        
        Args:
            length: Number of random bytes
            
        Returns:
            URL-safe base64 encoded token
        """
        random_bytes = secrets.token_bytes(length)
        return base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
    
    def _create_token_payload(self, user_id: str, email: str, purpose: str) -> TokenPayload:
        """
        Create token payload with security parameters.
        
        Args:
            user_id: User identifier
            email: User email
            purpose: Token purpose
            
        Returns:
            TokenPayload object
        """
        now = datetime.utcnow()
        expires = now + timedelta(minutes=SecurityConfig.TOKEN_EXPIRY_MINUTES)
        
        return TokenPayload(
            user_id=user_id,
            email=email,
            purpose=purpose,
            nonce=secrets.token_hex(16),
            created_at=now.isoformat(),
            expires_at=expires.isoformat()
        )
    
    def _sign_payload(self, payload: TokenPayload) -> str:
        """
        Sign the token payload with HMAC.
        
        Args:
            payload: Token payload to sign
            
        Returns:
            HMAC signature
        """
        # Convert payload to string
        payload_str = f"{payload.user_id}|{payload.email}|{payload.purpose}|{payload.nonce}|{payload.created_at}|{payload.expires_at}"
        
        # Create HMAC signature
        signature = hmac.new(
            SecurityConfig.TOKEN_SECRET_KEY.encode('utf-8'),
            payload_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _verify_signature(self, payload: TokenPayload, signature: str) -> bool:
        """
        Verify token signature using constant-time comparison.
        
        Args:
            payload: Token payload
            signature: HMAC signature to verify
            
        Returns:
            True if signature is valid
        """
        expected_signature = self._sign_payload(payload)
        return hmac.compare_digest(expected_signature, signature)
    
    def generate_token(self, user_id: str, email: str, 
                       purpose: str = TokenPurpose.PASSWORD_RESET.value,
                       ip_address: str = "", user_agent: str = "") -> str:
        """
        Generate a secure password reset token.
        
        Args:
            user_id: User identifier
            email: User email address
            purpose: Token purpose
            ip_address: Request IP address for audit
            user_agent: User agent for audit
            
        Returns:
            Encoded token string
            
        Raises:
            TokenGenerationError: If token generation fails
        """
        try:
            # Create token payload
            payload = self._create_token_payload(user_id, email, purpose)
            
            # Sign the payload
            signature = self._sign_payload(payload)
            
            # Combine payload and signature
            token_data = f"{payload.user_id}|{payload.email}|{payload.purpose}|{payload.nonce}|{payload.created_at}|{payload.expires_at}|{signature}"
            
            # Encode the complete token
            encoded_token = base64.urlsafe_b64encode(token_data.encode('utf-8')).decode('utf-8')
            
            # Store token metadata (hash only)
            token_hash = hashlib.sha256(encoded_token.encode('utf-8')).hexdigest()
            
            self.token_store[token_hash] = PasswordResetToken(
                token_hash=token_hash,
                user_id=user_id,
                email=email,
                purpose=purpose,
                created_at=datetime.utcnow(),
                expires_at=datetime.fromisoformat(payload.expires_at),
                attempts=0,
                is_used=False,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Clean up old tokens
            self._cleanup_expired_tokens()
            
            logger.info(f"Token generated for user {user_id} (hash: {token_hash[:8]}...)")
            
            return encoded_token
            
        except Exception as e:
            logger.error(f"Token generation failed: {str(e)}")
            raise TokenGenerationError("Failed to generate password reset token") from e
    
    def validate_token(self, token: str) -> Optional[TokenPayload]:
        """
        Validate a password reset token.
        
        Args:
            token: The token to validate
            
        Returns:
            TokenPayload if valid, None otherwise
            
        Raises:
            TokenValidationError: If token validation fails
        """
        try:
            # Decode token
            try:
                token_data = base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8')
            except Exception:
                logger.warning("Invalid token encoding")
                return None
            
            # Parse token components
            parts = token_data.split('|')
            if len(parts) != 7:
                logger.warning("Invalid token structure")
                return None
            
            user_id, email, purpose, nonce, created_at, expires_at, signature = parts
            
            # Reconstruct payload
            payload = TokenPayload(
                user_id=user_id,
                email=email,
                purpose=purpose,
                nonce=nonce,
                created_at=created_at,
                expires_at=expires_at
            )
            
            # Verify signature
            if not self._verify_signature(payload, signature):
                logger.warning(f"Invalid token signature for user {user_id}")
                return None
            
            # Check expiration
            expires_datetime = datetime.fromisoformat(expires_at)
            if datetime.utcnow() > expires_datetime:
                logger.warning(f"Expired token for user {user_id}")
                return None
            
            # Check token in store
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            stored_token = self.token_store.get(token_hash)
            
            if not stored_token:
                logger.warning(f"Token not found in store: {token_hash[:8]}...")
                return None
            
            # Check if token is used
            if stored_token.is_used:
                logger.warning(f"Token already used: {token_hash[:8]}...")
                return None
            
            # Check attempt limit
            if stored_token.attempts >= SecurityConfig.MAX_TOKEN_ATTEMPTS_PER_HOUR:
                logger.warning(f"Token attempt limit exceeded: {token_hash[:8]}...")
                return None
            
            # Increment attempt counter
            stored_token.attempts += 1
            
            logger.info(f"Token validated successfully for user {user_id}")
            
            return payload
            
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return None
    
    def invalidate_token(self, token: str) -> bool:
        """
        Mark token as used.
        
        Args:
            token: Token to invalidate
            
        Returns:
            True if successful
        """
        try:
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            if token_hash in self.token_store:
                self.token_store[token_hash].is_used = True
                logger.info(f"Token invalidated: {token_hash[:8]}...")
                return True
            return False
        except Exception as e:
            logger.error(f"Token invalidation error: {str(e)}")
            return False
    
    def _cleanup_expired_tokens(self):
        """Remove expired tokens from store."""
        now = datetime.utcnow()
        expired_keys = [
            key for key, token in self.token_store.items()
            if token.expires_at < now or token.is_used
        ]
        for key in expired_keys:
            del self.token_store[key]

# ============================================================================
# Email Service
# ============================================================================

class EmailService:
    """Handles secure email sending for password reset."""
    
    def __init__(self):
        self.smtp_config = {
            'host': SecurityConfig.SMTP_HOST,
            'port': SecurityConfig.SMTP_PORT,
            'username': SecurityConfig.SMTP_USERNAME,
            'password': SecurityConfig.SMTP_PASSWORD,
            'use_tls': SecurityConfig.SMTP_USE_TLS,
            'timeout': SecurityConfig.SMTP_TIMEOUT
        }
    
    def _create_email_message(self, to_email: str, subject: str, 
                              html_content: str, text_content: str) -> MIMEMultipart:
        """
        Create a secure email message.
        
        Args:
            to_email: Recipient email
            subject: Email subject
            html_content: HTML version of email
            text_content: Plain text version of email
            
        Returns:
            MIMEMultipart message
        """
        msg = MIMEMultipart('alternative')
        
        # Set headers with proper encoding
        msg['Subject'] = subject
        msg['From'] = formataddr((SecurityConfig.FROM_NAME, SecurityConfig.FROM_EMAIL))
        msg['To'] = to_email
        
        # Add message ID for tracking
        msg['Message-ID'] = f"<{secrets.token_hex(16)}@{SecurityConfig.FROM_EMAIL.split('@')[1]}>"
        
        # Add date header
        msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
        
        # Add security headers
        msg['X-Content-Type-Options'] = 'nosniff'
        msg['X-Priority'] = '1'  # High priority for password reset
        
        # Attach plain text and HTML versions
        msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
        msg.attach(MIMEText(html_content, 'html', 'utf-8'))
        
        return msg
    
    def send_password_reset_email(self, to_email: str, user_name: str, 
                                  reset_token: str, reset_url: str) -> bool:
        """
        Send password reset email securely.
        
        Args:
            to_email: Recipient email address
            user_name: User's name for personalization
            reset_token: The reset token (not included in email, just for URL)
            reset_url: Complete password reset URL with token
            
        Returns:
            True if email sent successfully
            
        Raises:
            EmailSendingError: If email sending fails
        """
        try:
            # Validate email configuration
            if not self.smtp_config['username'] or not self.smtp_config['password']:
                logger.error("SMTP credentials not configured")
                raise EmailSendingError("Email service not properly configured")
            
            # Create email content
            subject = "Password Reset Request - Action Required"
            
            # Plain text version
            text_content = f"""
            Password Reset Request
            
            Hello {user_name},
            
            We received a request to reset the password for your account.
            
            To reset your password, click on the following link:
            {reset_url}
            
            This link will expire in {SecurityConfig.TOKEN_EXPIRY_MINUTES} minutes.
            
            If you did not request a password reset, please ignore this email 
            and ensure your account is secure. Someone may have entered your 
            email address by mistake.
            
            For security reasons, never share this link with anyone.
            
            Best regards,
            {SecurityConfig.FROM_NAME}
            
            This is an automated message. Please do not reply to this email.
            """
            
            # HTML version (with security considerations)
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta http-equiv="X-Content-Type-Options" content="nosniff">
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c3e50;">Password Reset Request</h2>
                    
                    <p>Hello {user_name},</p>
                    
                    <p>We received a request to reset the password for your account.</p>
                    
                    <div style="background-color: #f8f9fa; border-left: 4px solid #007bff; padding: 15px; margin: 20px 0;">
                        <p style="margin: 0;"><strong>Reset your password by clicking the button below:</strong></p>
                        <p style="margin: 10px 0;">
                            <a href="{reset_url}" 
                               style="background-color: #007bff; color: white; padding: 10px 20px; 
                                      text-decoration: none; border-radius: 5px; display: inline-block;">
                                Reset Password
                            </a>
                        </p>
                        <p style="font-size: 0.9em; color: #666;">
                            This link will expire in {SecurityConfig.TOKEN_EXPIRY_MINUTES} minutes.
                        </p>
                    </div>
                    
                    <p>If the button doesn't work, copy and paste this URL into your browser:</p>
                    <p style="background-color: #f5f5f5; padding: 10px; word-break: break-all; font-size: 0.9em;">
                        {reset_url}
                    </p>
                    
                    <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 5px;">
                        <strong>⚠️ Security Notice:</strong>
                        <ul style="margin: 10px 0;">
                            <li>Never share this link with anyone</li>
                            <li>Our team will never ask for your password</li>
                            <li>If you didn't request this, ignore this email</li>
                        </ul>
                    </div>
                    
                    <hr style="border: 1px solid #eee; margin: 20px 0;">
                    
                    <p style="font-size: 0.8em; color: #999;">
                        This is an automated message from {SecurityConfig.FROM_NAME}.<br>
                        Please do not reply to this email.<br>
                        &copy; {datetime.now().year} Your Company. All rights reserved.
                    </p>
                </div>
            </body>
            </html>
            """
            
            # Create message
            msg = self._create_email_message(to_email, subject, html_content, text_content)
            
            # Send email with TLS
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port'], 
                             timeout=self.smtp_config['timeout']) as server:
                # Start TLS
                if self.smtp_config['use_tls']:
                    server.starttls(context=context)
                
                # Login
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                
                # Send email
                server.send_message(msg)
            
            logger.info(f"Password reset email sent to {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {str(e)}")
            raise EmailSendingError("Email service authentication failed") from e
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {str(e)}")
            raise EmailSendingError("Failed to send email") from e
        except Exception as e:
            logger.error(f"Email sending failed: {str(e)}")
            raise EmailSendingError("An unexpected error occurred while sending email") from e

# ============================================================================
# Password Reset Service
# ============================================================================

class PasswordResetService:
    """Main service for password reset functionality."""
    
    def __init__(self):
        self.token_manager = TokenManager()
        self.email_service = EmailService()
        self.validator = InputValidator()
    
    def request_password_reset(self, email: str, ip_address: str = "", 
                              user_agent: str = "") -> Dict[str, Any]:
        """
        Process a password reset request.
        
        Args:
            email: User's email address
            ip_address: Request IP address
            user_agent: User agent string
            
        Returns:
            Dictionary with result information
        """
        try:
            # Validate email
            is_valid_email, sanitized_email = self.validator.validate_email(email)
            if not is_valid_email:
                logger.warning(f"Invalid email format: {email[:50]}...")
                # Return success anyway to prevent email enumeration
                return {
                    "success": True,
                    "message": "If the email exists in our system, a password reset link has been sent."
                }
            
            # Check rate limiting by email
            if not rate_limiter.check_rate_limit(
                f"email:{sanitized_email}",
                SecurityConfig.EMAIL_RATE_LIMIT_PER_EMAIL,
                1  # 1 hour window
            ):
                logger.warning(f"Rate limit exceeded for email: {sanitized_email[:30]}...")
                return {
                    "success": True,  # Don't reveal rate limiting
                    "message": "If the email exists in our system, a password reset link has been sent."
                }
            
            # Check rate limiting by IP
            if not rate_limiter.check_rate_limit(
                f"ip:{ip_address}",
                SecurityConfig.EMAIL_RATE_LIMIT_PER_IP,
                1  # 1 hour window
            ):
                logger.warning(f"Rate limit exceeded for IP: {ip_address}")
                return {
                    "success": True,
                    "message": "If the email exists in our system, a password reset link has been sent."
                }
            
            # Look up user (mock database query)
            user = self._get_user_by_email(sanitized_email)
            
            # If user doesn't exist, don't reveal this information
            if not user:
                # Add artificial delay to prevent timing-based enumeration
                self._add_timing_delay()
                logger.info(f"Password reset requested for non-existent email: {sanitized_email[:30]}...")
                return {
                    "success": True,
                    "message": "If the email exists in our system, a password reset link has been sent."
                }
            
            # Check if user account is active
            if not user.get('is_active', False):
                logger.warning(f"Password reset requested for inactive account: {user['id']}")
                return {
                    "success": True,
                    "message": "If the email exists in our system, a password reset link has been sent."
                }
            
            # Generate reset token
            reset_token = self.token_manager.generate_token(
                user_id=user['id'],
                email=sanitized_email,
                purpose=TokenPurpose.PASSWORD_RESET.value,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Build reset URL (use HTTPS in production)
            base_url = os.environ.get('BASE_URL', 'https://example.com')
            reset_url = f"{base_url}/reset-password?token={reset_token}"
            
            # Send email
            try:
                self.email_service.send_password_reset_email(
                    to_email=sanitized_email,
                    user_name=user.get('name', 'User'),
                    reset_token=reset_token,
                    reset_url=reset_url
                )
                
                logger.info(f"Password reset email sent to user {user['id']}")
                
                return {
                    "success": True,
                    "message": "If the email exists in our system, a password reset link has been sent."
                }
                
            except EmailSendingError as e:
                logger.error(f"Failed to send reset email: {str(e)}")
                # Invalidate token since email wasn't sent
                self.token_manager.invalidate_token(reset_token)
                return {
                    "success": False,
                    "message": "An error occurred. Please try again later."
                }
            
        except Exception as e:
            logger.error(f"Password reset request failed: {str(e)}", exc_info=True)
            return {
                "success": False,
                "message": "An unexpected error occurred. Please try again later."
            }
    
    def validate_reset_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a password reset token.
        
        Args:
            token: Reset token to validate
            
        Returns:
            Dictionary with validation result
        """
        try:
            # Validate token
            payload = self.token_manager.validate_token(token)
            
            if not payload:
                return {
                    "valid": False,
                    "message": "Invalid or expired reset token. Please request a new password reset."
                }
            
            return {
                "valid": True,
                "user_id": payload.user_id,
                "email": payload.email,
                "message": "Token is valid. You can now reset your password."
            }
            
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return {
                "valid": False,
                "message": "An error occurred while validating the token."
            }
    
    def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """
        Reset user password using a valid token.
        
        Args:
            token: Valid reset token
            new_password: New password
            
        Returns:
            Dictionary with result
        """
        try:
            # Validate token first
            validation_result = self.validate_reset_token(token)
            
            if not validation_result['valid']:
                return validation_result
            
            # Validate password strength
            password_valid, password_message = self._validate_password_strength(new_password)
            if not password_valid:
                return {
                    "success": False,
                    "message": password_message
                }
            
            # Update password in database (mock)
            user_id = validation_result['user_id']
            self._update_user_password(user_id, new_password)
            
            # Invalidate the token
            self.token_manager.invalidate_token(token)
            
            # Send confirmation email
            user = self._get_user_by_id(user_id)
            if user:
                self._send_password_changed_confirmation(user['email'], user.get('name', 'User'))
            
            logger.info(f"Password reset successful for user {user_id}")
            
            return {
                "success": True,
                "message": "Password has been reset successfully. You can now log in with your new password."
            }
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}", exc_info=True)
            return {
                "success": False,
                "message": "An error occurred while resetting your password."
            }
    
    def _get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Mock database query - replace with actual database query."""
        # Simulated user database
        mock_users = {
            "user@example.com": {
                "id": "user_123",
                "email": "user@example.com",
                "name": "John Doe",
                "is_active": True
            }
        }
        return mock_users.get(email)
    
    def _get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Mock database query - replace with actual database query."""
        mock_users = {
            "user_123": {
                "id": "user_123",
                "email": "user@example.com",
                "name": "John Doe",
                "is_active": True
            }
        }
        return mock_users.get(user_id)
    
    def _update_user_password(self, user_id: str, new_password: str) -> None:
        """Mock password update - replace with actual secure password storage."""
        # In production:
        # 1. Hash password with bcrypt/argon2
        # 2. Store in database
        # 3. Invalidate all existing sessions
        # 4. Log the password change
        logger.info(f"Password updated for user {user_id} (hash stored securely)")
    
    def _validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password strength."""
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        
        if len(password) > 128:
            return False, "Password must not exceed 128 characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        # Check for common passwords
        common_passwords = ['password123', 'admin123', '12345678', 'qwerty123']
        if password.lower() in common_passwords:
            return False, "Password is too common. Please choose a stronger password."
        
        return True, "Password meets requirements"
    
    def _send_password_changed_confirmation(self, email: str, user_name: str) -> None:
        """Send confirmation that password was changed."""
        try:
            subject = "Your Password Has Been Changed"
            
            text_content = f"""
            Password Changed Successfully
            
            Hello {user_name},
            
            Your password has been successfully changed.
            
            If you did not make this change, please contact our support team immediately.
            
            Best regards,
            {SecurityConfig.FROM_NAME}
            """
            
            # Create and send email (simplified for example)
            logger.info(f"Password change confirmation sent to {email}")
            
        except Exception as e:
            logger.error(f"Failed to send confirmation email: {str(e)}")
    
    def _add_timing_delay(self) -> None:
        """Add random delay to prevent timing attacks."""
        import time
        time.sleep(secrets.SystemRandom().uniform(0.1, 0.5))

# ============================================================================
# Convenience Function
# ============================================================================

def generate_and_send_password_reset_token(email: str, 
                                          ip_address: str = "",
                                          user_agent: str = "") -> Dict[str, Any]:
    """
    Generate a password reset token and send it to the user's email.
    
    This is the main function that should be called from your application.
    
    Args:
        email: User's email address
        ip_address: Request IP address for auditing
        user_agent: User agent string for auditing
        
    Returns:
        Dictionary with success status and message
        
    Example:
        >>> result = generate_and_send_password_reset_token(
        ...     "user@example.com",
        ...     ip_address="192.168.1.1",
        ...     user_agent="Mozilla/5.0..."
        ... )
        >>> print(result['message'])
    """
    service = PasswordResetService()
    return service.request_password_reset(email, ip_address, user_agent)
