# =============================================
# Generated Code - Prompt 12 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 10:44 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

"""
api_logger.py - Secure API Request Logging Utility

Provides comprehensive logging of API requests with automatic PII/sensitive data
masking, log rotation, and structured logging support.
"""

import os
import re
import json
import time
import uuid
import hashlib
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Callable
from dataclasses import dataclass, field
from functools import wraps
from enum import Enum

# Optional imports for enhanced functionality
try:
    from flask import request, g, has_request_context
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

# ============================================================================
# Configuration
# ============================================================================

class LogLevel(Enum):
    """Log level enumeration"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

class LogFormat(Enum):
    """Supported log formats"""
    JSON = "json"
    TEXT = "text"
    STRUCTLOG = "structlog"

@dataclass
class LoggerConfig:
    """Configuration for API logger"""
    # Log file settings
    log_directory: str = "logs"
    log_filename: str = "api_requests.log"
    max_bytes: int = 10 * 1024 * 1024  # 10 MB
    backup_count: int = 10
    
    # Log level and format
    log_level: LogLevel = LogLevel.INFO
    log_format: LogFormat = LogFormat.JSON
    
    # Security settings
    mask_sensitive_data: bool = True
    mask_pii: bool = True
    hash_sensitive_fields: bool = False  # Hash instead of mask
    log_request_body: bool = True
    log_response_body: bool = False  # Usually disabled for security
    max_body_length: int = 10000  # Truncate large bodies
    log_headers: bool = False  # Usually disabled (contains auth tokens)
    allowed_headers: List[str] = field(default_factory=lambda: [
        'content-type', 'accept', 'user-agent', 'accept-language'
    ])
    
    # Performance
    async_logging: bool = False
    batch_size: int = 100
    flush_interval: int = 5  # seconds
    
    # Structured logging
    include_trace_id: bool = True
    include_request_id: bool = True
    application_name: str = "API"

# ============================================================================
# Sensitive Data Detection
# ============================================================================

class SensitiveDataDetector:
    """Detect and mask sensitive data in requests"""
    
    # Patterns for sensitive data
    SENSITIVE_PATTERNS = {
        'credit_card': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
        'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        'jwt_token': re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+'),
        'api_key': re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?secret)["\s:=]+([A-Za-z0-9+/=]{20,})'),
        'password': re.compile(r'(?i)(password|passwd|pwd|secret)["\s:=]+([^\s&]+)'),
        'token': re.compile(r'(?i)(token|auth|bearer)\s+([A-Za-z0-9\-._~+/]+=*)'),
        'private_key': re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    }
    
    # Fields that typically contain sensitive data
    SENSITIVE_FIELDS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'auth',
        'authorization', 'api_key', 'apikey', 'api_secret', 'apisecret',
        'access_token', 'refresh_token', 'private_key', 'secret_key',
        'credit_card', 'card_number', 'cvv', 'cvc', 'ssn', 'social_security',
        'birth_date', 'date_of_birth', 'dob', 'phone', 'phone_number',
        'email', 'address', 'passport', 'driver_license'
    }
    
    # Fields to hash instead of mask
    HASH_FIELDS = {'email', 'user_id', 'username'}
    
    @classmethod
    def mask_value(cls, value: Any, field_name: str = "", 
                   hash_sensitive: bool = False) -> Any:
        """Mask or hash sensitive values"""
        if value is None:
            return None
        
        # Handle different types
        if isinstance(value, dict):
            return cls.mask_dict(value, hash_sensitive)
        elif isinstance(value, list):
            return [cls.mask_value(item, field_name, hash_sensitive) for item in value]
        elif isinstance(value, str):
            return cls._mask_string(value, field_name, hash_sensitive)
        
        return value
    
    @classmethod
    def mask_dict(cls, data: Dict[str, Any], 
                  hash_sensitive: bool = False) -> Dict[str, Any]:
        """Mask sensitive data in dictionary"""
        if not data:
            return data
        
        masked = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if field name indicates sensitive data
            is_sensitive = any(
                sensitive_field in key_lower 
                for sensitive_field in cls.SENSITIVE_FIELDS
            )
            
            # Check if field should be hashed
            should_hash = any(
                hash_field in key_lower 
                for hash_field in cls.HASH_FIELDS
            ) or hash_sensitive
            
            if is_sensitive:
                if should_hash:
                    masked[key] = cls._hash_value(value)
                else:
                    masked[key] = cls._mask_value_by_type(value)
            else:
                masked[key] = cls.mask_value(value, key, hash_sensitive)
        
        return masked
    
    @classmethod
    def _mask_string(cls, value: str, field_name: str = "", 
                     hash_sensitive: bool = False) -> str:
        """Mask sensitive data in string"""
        if not value:
            return value
        
        # Apply pattern-based masking
        for pattern_name, pattern in cls.SENSITIVE_PATTERNS.items():
            if pattern.search(value):
                value = pattern.sub('[REDACTED]', value)
        
        return value
    
    @classmethod
    def _mask_value_by_type(cls, value: Any) -> Any:
        """Mask a value based on its type"""
        if isinstance(value, str):
            # Show first and last characters with asterisks
            if len(value) <= 4:
                return '*' * len(value)
            return value[:2] + '*' * (len(value) - 4) + value[-2:]
        elif isinstance(value, (int, float)):
            return '****'
        elif isinstance(value, bool):
            return '****'
        
        return '****'
    
    @classmethod
    def _hash_value(cls, value: Any) -> str:
        """Hash a value for privacy-preserving logging"""
        if isinstance(value, (str, int, float, bool)):
            value_str = str(value)
            return hashlib.sha256(value_str.encode()).hexdigest()[:16]
        return 'HASHED'
    
    @classmethod
    def sanitize_headers(cls, headers: Dict[str, str], 
                         allowed_headers: List[str]) -> Dict[str, str]:
        """Sanitize HTTP headers, keeping only allowed ones"""
        sanitized = {}
        
        for header, value in headers.items():
            header_lower = header.lower()
            
            # Always remove auth headers
            if header_lower in ('authorization', 'cookie', 'set-cookie', 
                               'x-api-key', 'x-auth-token'):
                sanitized[header] = '[REDACTED]'
            elif header_lower in allowed_headers:
                sanitized[header] = value
        
        return sanitized

# ============================================================================
# Request Context
# ============================================================================

class RequestContext:
    """Store request context for logging"""
    
    def __init__(self):
        self.request_id: str = str(uuid.uuid4())
        self.trace_id: Optional[str] = None
        self.start_time: Optional[float] = None
        self.user_id: Optional[str] = None
        self.client_ip: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.method: Optional[str] = None
        self.status_code: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary"""
        return {
            'request_id': self.request_id,
            'trace_id': self.trace_id,
            'user_id': self.user_id,
            'client_ip': self.client_ip,
            'endpoint': self.endpoint,
            'method': self.method,
            'status_code': self.status_code,
            'duration_ms': self.get_duration() if self.start_time else None
        }
    
    def get_duration(self) -> Optional[float]:
        """Get request duration in milliseconds"""
        if self.start_time:
            return (time.time() - self.start_time) * 1000
        return None

# ============================================================================
# Main API Logger
# ============================================================================

class APILogger:
    """
    Secure API request logger with automatic PII masking
    
    Usage:
        logger = APILogger()
        
        @logger.log_request
        def api_endpoint():
            return {'message': 'Success'}
    """
    
    def __init__(self, config: Optional[LoggerConfig] = None):
        self.config = config or LoggerConfig()
        self.detector = SensitiveDataDetector()
        self.logger = self._setup_logger()
        self._request_contexts: Dict[str, RequestContext] = {}
    
    def _setup_logger(self) -> logging.Logger:
        """Set up the logger with proper handlers"""
        logger = logging.getLogger(f"api_logger_{id(self)}")
        logger.setLevel(self.config.log_level.value)
        logger.propagate = False  # Don't propagate to root logger
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Create log directory if it doesn't exist
        log_dir = Path(self.config.log_directory)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up file handler with rotation
        log_file = log_dir / self.config.log_filename
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.config.max_bytes,
            backupCount=self.config.backup_count
        )
        
        # Set formatter based on format
        if self.config.log_format == LogFormat.JSON:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(TextFormatter())
        
        logger.addHandler(file_handler)
        
        # Add console handler for development
        if os.environ.get('ENV', '').lower() in ('development', 'dev'):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(TextFormatter(colors=True))
            logger.addHandler(console_handler)
        
        # Add structlog handler if available
        if STRUCTLOG_AVAILABLE and self.config.log_format == LogFormat.STRUCTLOG:
            structlog.configure(
                processors=[
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.processors.UnicodeDecoder(),
                    structlog.processors.JSONRenderer()
                ],
                context_class=dict,
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
        
        return logger
    
    def log_request(self, func_or_level=None, **kwargs):
        """
        Decorator to log API requests
        
        Can be used as @log_request or @log_request(level=LogLevel.DEBUG)
        """
        if callable(func_or_level):
            return self._decorate_request(func_or_level)
        
        level = func_or_level or LogLevel.INFO
        return lambda f: self._decorate_request(f, level=level)
    
    def _decorate_request(self, func: Callable, level: LogLevel = LogLevel.INFO):
        """Internal decorator implementation"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create request context
            context = RequestContext()
            context.start_time = time.time()
            
            # Extract request information if Flask is available
            if FLASK_AVAILABLE and has_request_context():
                self._extract_flask_context(context)
            
            # Log the incoming request
            self._log_incoming_request(context, func.__name__)
            
            try:
                # Execute the function
                response = func(*args, **kwargs)
                
                # Extract status code if available
                if FLASK_AVAILABLE and has_request_context():
                    context.status_code = getattr(response, 'status_code', 200)
                
                # Log successful response
                self._log_response(context, response, level)
                
                return response
                
            except Exception as e:
                # Log error
                context.status_code = 500
                self._log_error(context, e)
                raise
        
        return wrapper
    
    def _extract_flask_context(self, context: RequestContext):
        """Extract request information from Flask"""
        context.method = request.method
        context.endpoint = request.endpoint
        context.client_ip = self._get_client_ip()
        
        # Extract trace ID from headers if present
        context.trace_id = request.headers.get('X-Trace-ID') or request.headers.get('X-Request-ID')
        
        # Extract user ID if available
        if hasattr(g, 'current_user') and g.current_user:
            context.user_id = str(getattr(g.current_user, 'id', 'unknown'))
    
    def _get_client_ip(self) -> str:
        """Safely extract client IP address"""
        if not FLASK_AVAILABLE or not has_request_context():
            return 'unknown'
        
        # Check common proxy headers
        for header in ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP']:
            ip = request.headers.get(header)
            if ip:
                return ip.split(',')[0].strip()
        
        return request.remote_addr or 'unknown'
    
    def _log_incoming_request(self, context: RequestContext, func_name: str):
        """Log incoming API request"""
        log_data = {
            'event': 'incoming_request',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'function': func_name,
            **context.to_dict()
        }
        
        # Log request body if configured
        if self.config.log_request_body and FLASK_AVAILABLE and has_request_context():
            body = self._get_request_body()
            if body:
                log_data['request_body'] = self._sanitize_data(body)
        
        # Log headers if configured
        if self.config.log_headers and FLASK_AVAILABLE and has_request_context():
            headers = dict(request.headers)
            log_data['headers'] = self.detector.sanitize_headers(
                headers, 
                self.config.allowed_headers
            )
        
        # Log query parameters
        if FLASK_AVAILABLE and has_request_context() and request.args:
            log_data['query_params'] = self._sanitize_data(dict(request.args))
        
        self._log(logging.INFO, log_data)
    
    def _log_response(self, context: RequestContext, response: Any, 
                      level: LogLevel = LogLevel.INFO):
        """Log API response"""
        log_data = {
            'event': 'request_completed',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            **context.to_dict()
        }
        
        # Log response body if configured (usually disabled)
        if self.config.log_response_body and response:
            try:
                if isinstance(response, dict):
                    log_data['response_body'] = self._sanitize_data(response)
                elif hasattr(response, 'get_json'):
                    log_data['response_body'] = self._sanitize_data(response.get_json())
            except Exception:
                pass
        
        self._log(level.value, log_data)
    
    def _log_error(self, context: RequestContext, error: Exception):
        """Log API error"""
        log_data = {
            'event': 'request_error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error_type': type(error).__name__,
            'error_message': str(error),
            **context.to_dict()
        }
        
        # Include request body for debugging (sanitized)
        if FLASK_AVAILABLE and has_request_context():
            body = self._get_request_body()
            if body:
                log_data['request_body'] = self._sanitize_data(body)
        
        self._log(logging.ERROR, log_data)
    
    def _get_request_body(self) -> Optional[Dict]:
        """Safely get request body"""
        try:
            if request.is_json:
                return request.get_json()
            elif request.form:
                return dict(request.form)
            elif request.data:
                # Try to parse as JSON
                try:
                    return json.loads(request.data)
                except:
                    # Truncate raw data
                    raw = request.data.decode('utf-8', errors='ignore')
                    return {'raw_data': raw[:self.config.max_body_length]}
        except Exception:
            pass
        return None
    
    def _sanitize_data(self, data: Any) -> Any:
        """Sanitize data for logging"""
        if data is None:
            return None
        
        # Truncate string values
        if isinstance(data, str):
            return data[:self.config.max_body_length]
        
        # Mask sensitive data
        if self.config.mask_sensitive_data:
            if isinstance(data, dict):
                return self.detector.mask_dict(
                    data, 
                    hash_sensitive=self.config.hash_sensitive_fields
                )
            elif isinstance(data, list):
                return [
                    self._sanitize_data(item) for item in data
                ]
        
        return data
    
    def _log(self, level: int, data: Dict[str, Any]):
        """Internal logging method"""
        try:
            if STRUCTLOG_AVAILABLE and self.config.log_format == LogFormat.STRUCTLOG:
                structlog.get_logger().log(level, **data)
            else:
                self.logger.log(level, json.dumps(data, default=str))
        except Exception as e:
            # Fallback to basic logging if structured logging fails
            self.logger.error(f"Logging error: {e}")
    
    def log_custom(self, event: str, level: LogLevel = LogLevel.INFO, 
                   **extra_data):
        """Log custom events with context"""
        context = RequestContext()
        
        if FLASK_AVAILABLE and has_request_context():
            self._extract_flask_context(context)
        
        log_data = {
            'event': event,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            **context.to_dict(),
            **extra_data
        }
        
        # Sanitize any sensitive data in extra fields
        if self.config.mask_sensitive_data:
            log_data = self._sanitize_data(log_data)
        
        self._log(level.value, log_data)

# ============================================================================
# Formatters
# ============================================================================

class JSONFormatter(logging.Formatter):
    """JSON log formatter"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        try:
            # Try to parse the message as JSON
            log_entry = json.loads(record.getMessage())
            log_entry['logger'] = record.name
            log_entry['level'] = record.levelname
            return json.dumps(log_entry, default=str)
        except:
            # Fallback to regular format
            return super().format(record)

class TextFormatter(logging.Formatter):
    """Human-readable text formatter with optional colors"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def __init__(self, colors: bool = False):
        super().__init__()
        self.colors = colors
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as text"""
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        # Add color if enabled
        level = record.levelname
        if self.colors and level in self.COLORS:
            level = f"{self.COLORS[level]}{level}{self.COLORS['RESET']}"
        
        # Try to format JSON nicely
        try:
            data = json.loads(record.getMessage())
            formatted_data = json.dumps(data, indent=2, default=str)
            return f"[{timestamp}] {level} - {formatted_data}"
        except:
            return f"[{timestamp}] {level} - {record.getMessage()}"

# ============================================================================
# Async Logger (Optional)
# ============================================================================

class AsyncAPILogger(APILogger):
    """Async version of API logger using background threads"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._log_queue = []
        import threading
        self._lock = threading.Lock()
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
    
    def _log(self, level: int, data: Dict[str, Any]):
        """Queue log entry for async processing"""
        with self._lock:
            self._log_queue.append((level, data))
            
            # Auto-flush if batch size reached
            if len(self._log_queue) >= self.config.batch_size:
                self._flush()
    
    def _flush(self):
        """Flush queued log entries"""
        with self._lock:
            if not self._log_queue:
                return
            
            entries = self._log_queue.copy()
            self._log_queue.clear()
        
        for level, data in entries:
            super()._log(level, data)
    
    def _flush_loop(self):
        """Background flush loop"""
        while True:
            time.sleep(self.config.flush_interval)
            self._flush()

# ============================================================================
# Middleware for Flask/Django
# ============================================================================

class APILoggingMiddleware:
    """
    WSGI middleware for automatic API request logging
    
    Usage with Flask:
        app = Flask(__name__)
        app.wsgi_app = APILoggingMiddleware(app.wsgi_app)
    """
    
    def __init__(self, app, logger: Optional[APILogger] = None):
        self.app = app
        self.logger = logger or APILogger()
    
    def __call__(self, environ, start_response):
        # Create request context
        context = RequestContext()
        context.start_time = time.time()
        context.method = environ.get('REQUEST_METHOD')
        context.endpoint = environ.get('PATH_INFO')
        context.client_ip = environ.get('REMOTE_ADDR')
        
        # Wrap start_response to capture status code
        def custom_start_response(status, headers, exc_info=None):
            context.status_code = int(status.split(' ')[0])
            
            # Log the response
            self.logger._log_response(context, None)
            
            return start_response(status, headers, exc_info)
        
        # Log the request
        self.logger._log_incoming_request(context, '')
        
        return self.app(environ, custom_start_response)

# ============================================================================
# Audit Logger
# ============================================================================

class AuditLogger:
    """
    Specialized logger for security audit trails
    
    Logs all security-relevant events with immutable audit trail.
    """
    
    def __init__(self, log_directory: str = "audit"):
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)
        self._setup_audit_logger()
    
    def _setup_audit_logger(self):
        """Set up audit logger with append-only file"""
        self.logger = logging.getLogger('audit_logger')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        
        # Use a handler that ensures append-only logging
        audit_file = self.log_directory / 'audit.log'
        handler = logging.FileHandler(audit_file, mode='a')
        handler.setFormatter(JSONFormatter())
        self.logger.addHandler(handler)
    
    def log_security_event(self, event_type: str, user_id: Optional[str] = None,
                          success: bool = True, details: Optional[Dict] = None,
                          severity: str = "INFO"):
        """Log a security-relevant event"""
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'severity': severity,
            'success': success,
            'user_id': user_id,
            'client_ip': self._get_client_ip(),
            'user_agent': self._get_user_agent(),
            'details': details or {}
        }
        
        self.logger.info(json.dumps(event, default=str))
    
    def _get_client_ip(self) -> str:
        """Get client IP if available"""
        if FLASK_AVAILABLE and has_request_context():
            return request.remote_addr
        return 'unknown'
    
    def _get_user_agent(self) -> str:
        """Get user agent if available"""
        if FLASK_AVAILABLE and has_request_context():
            return request.headers.get('User-Agent', 'unknown')
        return 'unknown'
    
    def log_login_attempt(self, user_id: str, success: bool, details: Optional[Dict] = None):
        """Log login attempt"""
        self.log_security_event(
            'login_attempt',
            user_id=user_id,
            success=success,
            details=details,
            severity='WARNING' if not success else 'INFO'
        )
    
    def log_permission_denied(self, user_id: str, resource: str, action: str):
        """Log permission denied events"""
        self.log_security_event(
            'permission_denied',
            user_id=user_id,
            success=False,
            severity='WARNING',
            details={
                'resource': resource,
                'action': action
            }
        )
    
    def log_data_access(self, user_id: str, data_type: str, record_id: str):
        """Log access to sensitive data"""
        self.log_security_event(
            'data_access',
            user_id=user_id,
            success=True,
            severity='INFO',
            details={
                'data_type': data_type,
                'record_id': record_id
            }
        )
    
    def log_configuration_change(self, user_id: str, setting: str, 
                                old_value: str = '[REDACTED]', 
                                new_value: str = '[REDACTED]'):
        """Log configuration changes"""
        self.log_security_event(
            'config_change',
            user_id=user_id,
            success=True,
            severity='WARNING',
            details={
                'setting': setting,
                'old_value': old_value,
                'new_value': new_value
            }
        )

# ============================================================================
# Factory Functions
# ============================================================================

def create_api_logger(
    log_directory: str = "logs",
    log_level: str = "INFO",
    mask_sensitive: bool = True,
    log_format: str = "json",
    **kwargs
) -> APILogger:
    """
    Factory function to create an API logger
    
    Usage:
        logger = create_api_logger(
            log_directory="/var/log/myapp",
            log_level="INFO",
            mask_sensitive=True
        )
    """
    config = LoggerConfig(
        log_directory=log_directory,
        log_level=LogLevel[log_level.upper()],
        log_format=LogFormat(log_format.lower()),
        mask_sensitive_data=mask_sensitive,
        **kwargs
    )
    
    return APILogger(config)

# ============================================================================
# Usage Examples
# ============================================================================

# Example 1: Basic usage with Flask
"""
from flask import Flask, request, jsonify
from api_logger import create_api_logger

app = Flask(__name__)
logger = create_api_logger()

@app.route('/api/users', methods=['POST'])
@logger.log_request
def create_user():
    data = request.get_json()
    # Process user creation...
    return jsonify({'message': 'User created', 'user_id': 123})

@app.route('/api/users/<int:user_id>', methods=['GET'])
@logger.log_request(level=LogLevel.DEBUG)
def get_user(user_id):
    # Log custom event
    logger.log_custom('user_accessed', user_id=user_id)
    return jsonify({'user_id': user_id, 'name': 'John Doe'})
"""

# Example 2: Using middleware
"""
from flask import Flask
from api_logger import APILoggingMiddleware

app = Flask(__name__)
app.wsgi_app = APILoggingMiddleware(app.wsgi_app)
"""

# Example 3: Audit logging
"""
from api_logger import AuditLogger

audit = AuditLogger()

@app.route('/admin/settings', methods=['POST'])
@login_required
def update_settings():
    old_value = get_setting('max_users')
    new_value = request.json['max_users']
    
    # Update setting...
    
    audit.log_configuration_change(
        user_id=current_user.id,
        setting='max_users',
        old_value=str(old_value),
        new_value=str(new_value)
    )
"""

if __name__ == "__main__":
    # Test the logger
    print("Testing API Logger...")
    
    # Create logger
    logger = create_api_logger(
        log_directory="./test_logs",
        log_level="DEBUG",
        log_format="text"
    )
    
    # Test sensitive data masking
    test_data = {
        "username": "john_doe",
        "password": "secret123",
        "email": "john@example.com",
        "credit_card": "4111-1111-1111-1111",
        "api_key": "sk_live_abcdef123456",
        "nested": {
            "token": "eyJhbGciOiJIUzI1NiIs...",
            "ssn": "123-45-6789"
        }
    }
    
    print("\nOriginal data:")
    print(json.dumps(test_data, indent=2))
    
    print("\nMasked data:")
    masked = logger._sanitize_data(test_data)
    print(json.dumps(masked, indent=2))
    
    print("\nLog files created in ./test_logs/")