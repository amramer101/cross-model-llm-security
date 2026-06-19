# =============================================
# Generated Code - Prompt 12 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

"""
api_request_logger.py
A comprehensive logging utility for recording API requests with payload details,
supporting multiple frameworks, formats, and storage backends.
"""

import json
import logging
import time
import uuid
import gzip
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Union, Callable, List
from functools import wraps
from dataclasses import dataclass, field, asdict
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import re
import hashlib
import threading
from queue import Queue
from contextlib import contextmanager
import sqlite3
import pickle


@dataclass
class APIRequestLog:
    """Data structure for API request log entry."""
    request_id: str
    timestamp: str
    method: str
    endpoint: str
    client_ip: str
    user_agent: str
    request_headers: Dict[str, str]
    query_params: Dict[str, Any]
    request_body: Any
    response_status: Optional[int] = None
    response_body: Optional[Any] = None
    response_time_ms: Optional[float] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    extra_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, handling non-serializable objects."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string with proper error handling."""
        def default_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, bytes):
                return obj.decode('utf-8', errors='ignore')
            return str(obj)
        
        return json.dumps(self.to_dict(), default=default_serializer, indent=2)


class SensitiveDataFilter:
    """Filter and mask sensitive data from request/response payloads."""
    
    SENSITIVE_FIELDS = {
        'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
        'auth', 'authorization', 'credit_card', 'card_number', 'cvv',
        'ssn', 'social_security', 'access_token', 'refresh_token',
        'private_key', 'jwt', 'session_id', 'cookie'
    }
    
    SENSITIVE_PATTERNS = [
        (re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'), '[CREDIT_CARD]'),  # Credit card
        (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN]'),  # SSN
        (re.compile(r'Bearer\s+[^\s]+'), 'Bearer [REDACTED]'),  # Bearer tokens
        (re.compile(r'Basic\s+[^\s]+'), 'Basic [REDACTED]'),  # Basic auth
    ]
    
    @classmethod
    def mask_sensitive_data(cls, data: Any, depth: int = 0, max_depth: int = 10) -> Any:
        """
        Recursively mask sensitive data in dictionaries, lists, and strings.
        
        Args:
            data: Data to mask
            depth: Current recursion depth
            max_depth: Maximum recursion depth
        
        Returns:
            Data with sensitive information masked
        """
        if depth > max_depth:
            return '[MAX_DEPTH_REACHED]'
        
        if isinstance(data, dict):
            masked_dict = {}
            for key, value in data.items():
                # Check if key is sensitive
                if key.lower() in cls.SENSITIVE_FIELDS or any(
                    sensitive in key.lower() for sensitive in cls.SENSITIVE_FIELDS
                ):
                    masked_dict[key] = '[REDACTED]'
                else:
                    masked_dict[key] = cls.mask_sensitive_data(value, depth + 1, max_depth)
            return masked_dict
        
        elif isinstance(data, list):
            return [cls.mask_sensitive_data(item, depth + 1, max_depth) for item in data]
        
        elif isinstance(data, str):
            # Apply regex patterns to strings
            masked_str = data
            for pattern, replacement in cls.SENSITIVE_PATTERNS:
                masked_str = pattern.sub(replacement, masked_str)
            return masked_str
        
        elif isinstance(data, bytes):
            try:
                # Try to decode and mask
                decoded = data.decode('utf-8', errors='ignore')
                return cls.mask_sensitive_data(decoded, depth, max_depth)
            except:
                return '[BINARY_DATA]'
        
        return data


class LogFormatter:
    """Custom formatters for API request logs."""
    
    @staticmethod
    def json_format(log_entry: APIRequestLog) -> str:
        """Format log entry as JSON."""
        return log_entry.to_json()
    
    @staticmethod
    def key_value_format(log_entry: APIRequestLog) -> str:
        """Format log entry as key-value pairs."""
        return (
            f"request_id={log_entry.request_id} "
            f"timestamp={log_entry.timestamp} "
            f"method={log_entry.method} "
            f"endpoint={log_entry.endpoint} "
            f"client_ip={log_entry.client_ip} "
            f"status={log_entry.response_status} "
            f"response_time={log_entry.response_time_ms}ms"
        )
    
    @staticmethod
    def apache_format(log_entry: APIRequestLog) -> str:
        """Format log entry in Apache combined log format."""
        return (
            f'{log_entry.client_ip} - {log_entry.user_id or "-"} '
            f'[{log_entry.timestamp}] '
            f'"{log_entry.method} {log_entry.endpoint} HTTP/1.1" '
            f'{log_entry.response_status or 0} '
            f'{len(str(log_entry.response_body)) if log_entry.response_body else 0} '
            f'"{log_entry.user_agent}" '
            f'{log_entry.response_time_ms or 0}ms'
        )


class LogStorage:
    """Base class for log storage backends."""
    
    def write(self, log_entry: APIRequestLog):
        """Write a log entry to storage."""
        raise NotImplementedError
    
    def close(self):
        """Close the storage connection."""
        pass


class FileLogStorage(LogStorage):
    """Store logs in rotating files."""
    
    def __init__(self, 
                 log_dir: str = "logs",
                 filename_template: str = "api_requests_{date}.log",
                 max_file_size: int = 100 * 1024 * 1024,  # 100 MB
                 backup_count: int = 30,
                 compress: bool = True,
                 format_type: str = "json"):
        """
        Initialize file-based log storage.
        
        Args:
            log_dir: Directory for log files
            filename_template: Template for log filenames
            max_file_size: Maximum file size before rotation
            backup_count: Number of backup files to keep
            compress: Whether to compress rotated files
            format_type: Log format type ('json', 'key_value', 'apache')
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.filename_template = filename_template
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        self.compress = compress
        self.format_type = format_type
        
        # Set up formatter
        format_map = {
            'json': LogFormatter.json_format,
            'key_value': LogFormatter.key_value_format,
            'apache': LogFormatter.apache_format
        }
        self.formatter = format_map.get(format_type, LogFormatter.json_format)
        
        # Thread-safe file writing
        self._lock = threading.Lock()
        self._current_file = None
        self._current_file_date = None
    
    def _get_filename(self) -> str:
        """Get the current log filename based on date."""
        date_str = datetime.now().strftime("%Y%m%d")
        return self.log_dir / self.filename_template.format(date=date_str)
    
    def _rotate_if_needed(self):
        """Check and perform log rotation if needed."""
        current_file = self._get_filename()
        
        if current_file.exists() and current_file.stat().st_size >= self.max_file_size:
            # Rotate the file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_name = current_file.with_suffix(f".{timestamp}.log")
            current_file.rename(rotated_name)
            
            if self.compress:
                # Compress the rotated file
                import gzip
                import shutil
                
                with open(rotated_name, 'rb') as f_in:
                    with gzip.open(f"{rotated_name}.gz", 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                rotated_name.unlink()  # Remove uncompressed file
            
            # Clean up old backups
            self._cleanup_old_logs()
    
    def _cleanup_old_logs(self):
        """Remove old log files exceeding backup count."""
        log_files = sorted(
            self.log_dir.glob("*.log*"),
            key=os.path.getmtime,
            reverse=True
        )
        
        for old_file in log_files[self.backup_count:]:
            try:
                old_file.unlink()
            except Exception:
                pass
    
    def write(self, log_entry: APIRequestLog):
        """Write a log entry to file."""
        with self._lock:
            self._rotate_if_needed()
            
            formatted_entry = self.formatter(log_entry) + "\n"
            
            try:
                with open(self._get_filename(), 'a') as f:
                    f.write(formatted_entry)
            except Exception as e:
                # Fallback to stderr if file writing fails
                import sys
                print(f"Failed to write to log file: {e}", file=sys.stderr)


class SQLiteLogStorage(LogStorage):
    """Store logs in SQLite database."""
    
    def __init__(self, db_path: str = "logs/api_requests.db"):
        """
        Initialize SQLite log storage.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    method TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    request_headers TEXT,
                    query_params TEXT,
                    request_body TEXT,
                    response_status INTEGER,
                    response_body TEXT,
                    response_time_ms REAL,
                    user_id TEXT,
                    session_id TEXT,
                    error_message TEXT,
                    extra_metadata TEXT
                )
            """)
            
            # Create indexes for common queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON api_requests(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_endpoint 
                ON api_requests(endpoint)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_response_status 
                ON api_requests(response_status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_id 
                ON api_requests(user_id)
            """)
            conn.commit()
    
    def write(self, log_entry: APIRequestLog):
        """Write a log entry to database."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO api_requests (
                            request_id, timestamp, method, endpoint,
                            client_ip, user_agent, request_headers,
                            query_params, request_body, response_status,
                            response_body, response_time_ms, user_id,
                            session_id, error_message, extra_metadata
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        log_entry.request_id,
                        log_entry.timestamp,
                        log_entry.method,
                        log_entry.endpoint,
                        log_entry.client_ip,
                        log_entry.user_agent,
                        json.dumps(log_entry.request_headers),
                        json.dumps(log_entry.query_params),
                        json.dumps(log_entry.request_body) if log_entry.request_body else None,
                        log_entry.response_status,
                        json.dumps(log_entry.response_body) if log_entry.response_body else None,
                        log_entry.response_time_ms,
                        log_entry.user_id,
                        log_entry.session_id,
                        log_entry.error_message,
                        json.dumps(log_entry.extra_metadata)
                    ))
            except Exception as e:
                import sys
                print(f"Failed to write to database: {e}", file=sys.stderr)


class AsyncLogWriter:
    """Asynchronous log writer using a background thread."""
    
    def __init__(self, storage: LogStorage, max_queue_size: int = 10000):
        """
        Initialize async log writer.
        
        Args:
            storage: Log storage backend
            max_queue_size: Maximum queue size before blocking
        """
        self.storage = storage
        self.queue = Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._process_queue, daemon=True)
        self._thread.start()
    
    def _process_queue(self):
        """Process log entries from queue."""
        while not self._stop_event.is_set():
            try:
                log_entry = self.queue.get(timeout=1)
                if log_entry is None:  # Sentinel value for shutdown
                    break
                self.storage.write(log_entry)
                self.queue.task_done()
            except Exception:
                # Queue timeout, check stop event
                continue
    
    def write(self, log_entry: APIRequestLog):
        """Add log entry to queue."""
        try:
            self.queue.put(log_entry, timeout=5)
        except Exception:
            # Queue is full, log to stderr as fallback
            import sys
            print(f"Log queue full, dropping entry: {log_entry.request_id}", file=sys.stderr)
    
    def stop(self):
        """Stop the async writer and flush remaining logs."""
        self._stop_event.set()
        self.queue.put(None)  # Sentinel to stop thread
        self._thread.join(timeout=10)
        self.storage.close()


class APIRequestLogger:
    """Main API request logger with multiple framework support."""
    
    def __init__(self,
                 storage: Optional[LogStorage] = None,
                 mask_sensitive: bool = True,
                 log_request_body: bool = True,
                 log_response_body: bool = True,
                 max_body_size: int = 1024 * 1024,  # 1 MB
                 async_write: bool = True,
                 sample_rate: float = 1.0):
        """
        Initialize API request logger.
        
        Args:
            storage: Log storage backend (defaults to file storage)
            mask_sensitive: Whether to mask sensitive data
            log_request_body: Whether to log request bodies
            log_response_body: Whether to log response bodies
            max_body_size: Maximum body size to log
            async_write: Whether to write logs asynchronously
            sample_rate: Sampling rate (0.0 to 1.0) for high-traffic scenarios
        """
        self.mask_sensitive = mask_sensitive
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body
        self.max_body_size = max_body_size
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        
        # Set up storage
        if storage is None:
            storage = FileLogStorage()
        
        self.storage = AsyncLogWriter(storage) if async_write else storage
    
    def _should_sample(self) -> bool:
        """Determine if this request should be logged based on sample rate."""
        if self.sample_rate >= 1.0:
            return True
        import random
        return random.random() < self.sample_rate
    
    def _truncate_body(self, body: Any) -> Any:
        """Truncate body if it exceeds maximum size."""
        if isinstance(body, (str, bytes)):
            if len(body) > self.max_body_size:
                truncated = body[:self.max_body_size]
                return f"{truncated}...[TRUNCATED at {self.max_body_size} bytes]"
        return body
    
    def _extract_request_data(self, request, framework: str = "flask") -> Dict[str, Any]:
        """
        Extract request data based on framework.
        
        Args:
            request: Framework-specific request object
            framework: Framework name ('flask', 'django', 'fastapi')
        
        Returns:
            Dictionary with extracted request data
        """
        data = {
            'request_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'client_ip': self._get_client_ip(request, framework),
            'user_agent': self._get_user_agent(request, framework),
        }
        
        if framework == "flask":
            data.update({
                'method': request.method,
                'endpoint': request.path,
                'request_headers': dict(request.headers),
                'query_params': dict(request.args),
                'request_body': request.get_data(as_text=True) if self.log_request_body else None,
            })
        
        elif framework == "django":
            data.update({
                'method': request.method,
                'endpoint': request.path,
                'request_headers': dict(request.headers),
                'query_params': dict(request.GET),
                'request_body': request.body.decode('utf-8') if self.log_request_body else None,
            })
        
        elif framework == "fastapi":
            from fastapi import Request as FastAPIRequest
            data.update({
                'method': request.method,
                'endpoint': str(request.url.path),
                'request_headers': dict(request.headers),
                'query_params': dict(request.query_params),
                'request_body': None,  # Body must be awaited, handled separately
            })
        
        return data
    
    def _get_client_ip(self, request, framework: str) -> str:
        """Extract client IP from request."""
        if framework == "flask":
            return request.remote_addr or 'unknown'
        elif framework == "django":
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                return x_forwarded_for.split(',')[0].strip()
            return request.META.get('REMOTE_ADDR', 'unknown')
        elif framework == "fastapi":
            return request.client.host if request.client else 'unknown'
        return 'unknown'
    
    def _get_user_agent(self, request, framework: str) -> str:
        """Extract user agent from request."""
        if framework in ("flask", "fastapi"):
            return request.headers.get('User-Agent', 'unknown')
        elif framework == "django":
            return request.META.get('HTTP_USER_AGENT', 'unknown')
        return 'unknown'
    
    def log_request(self, 
                    request,
                    framework: str = "flask",
                    user_id: Optional[str] = None,
                    session_id: Optional[str] = None,
                    extra_metadata: Optional[Dict[str, Any]] = None) -> APIRequestLog:
        """
        Log an API request.
        
        Args:
            request: Framework-specific request object
            framework: Framework name ('flask', 'django', 'fastapi')
            user_id: Authenticated user ID
            session_id: Session ID
            extra_metadata: Additional metadata to log
        
        Returns:
            APIRequestLog object
        """
        if not self._should_sample():
            return None
        
        # Extract request data
        request_data = self._extract_request_data(request, framework)
        
        # Create log entry
        log_entry = APIRequestLog(
            request_id=request_data['request_id'],
            timestamp=request_data['timestamp'],
            method=request_data['method'],
            endpoint=request_data['endpoint'],
            client_ip=request_data['client_ip'],
            user_agent=request_data['user_agent'],
            request_headers=request_data['request_headers'],
            query_params=request_data['query_params'],
            request_body=self._truncate_body(request_data['request_body']),
            user_id=user_id,
            session_id=session_id,
            extra_metadata=extra_metadata or {}
        )
        
        # Mask sensitive data if enabled
        if self.mask_sensitive:
            log_entry.request_headers = SensitiveDataFilter.mask_sensitive_data(
                log_entry.request_headers
            )
            log_entry.request_body = SensitiveDataFilter.mask_sensitive_data(
                log_entry.request_body
            )
            log_entry.query_params = SensitiveDataFilter.mask_sensitive_data(
                log_entry.query_params
            )
        
        # Store the log entry for later update with response data
        request._api_log_entry = log_entry
        
        return log_entry
    
    def log_response(self,
                     request,
                     response,
                     framework: str = "flask",
                     start_time: Optional[float] = None):
        """
        Log response data and write complete log entry.
        
        Args:
            request: Framework-specific request object
            response: Framework-specific response object
            framework: Framework name
            start_time: Request start time for calculating response time
        """
        log_entry = getattr(request, '_api_log_entry', None)
        if not log_entry:
            return
        
        # Calculate response time
        if start_time:
            log_entry.response_time_ms = (time.time() - start_time) * 1000
        
        # Extract response data
        if framework in ("flask", "django"):
            log_entry.response_status = response.status_code
            if self.log_response_body:
                try:
                    log_entry.response_body = response.get_data(as_text=True)
                except:
                    log_entry.response_body = str(response.content)
        
        elif framework == "fastapi":
            log_entry.response_status = response.status_code
            # FastAPI response body handling differs
        
        # Truncate and mask response body
        if log_entry.response_body:
            log_entry.response_body = self._truncate_body(log_entry.response_body)
            if self.mask_sensitive:
                log_entry.response_body = SensitiveDataFilter.mask_sensitive_data(
                    log_entry.response_body
                )
        
        # Write the complete log entry
        self.storage.write(log_entry)


# Decorators for easy integration

class FlaskRequestLogger:
    """Flask-specific request logger integration."""
    
    def __init__(self, api_logger: APIRequestLogger):
        self.api_logger = api_logger
    
    def log_request_response(self, f):
        """Decorator to log Flask request/response."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, g
            
            start_time = time.time()
            
            # Log request
            self.api_logger.log_request(
                request,
                framework="flask",
                user_id=getattr(g, 'user_id', None),
                session_id=getattr(g, 'session_id', None)
            )
            
            try:
                response = f(*args, **kwargs)
                
                # Log response
                self.api_logger.log_response(
                    request,
                    response,
                    framework="flask",
                    start_time=start_time
                )
                
                return response
            
            except Exception as e:
                # Log error
                log_entry = getattr(request, '_api_log_entry', None)
                if log_entry:
                    log_entry.response_status = 500
                    log_entry.error_message = str(e)
                    log_entry.response_time_ms = (time.time() - start_time) * 1000
                    self.api_logger.storage.write(log_entry)
                raise
        
        return decorated_function


class FastAPIRequestLogger:
    """FastAPI-specific request logger middleware."""
    
    def __init__(self, api_logger: APIRequestLogger):
        self.api_logger = api_logger
    
    async def __call__(self, request, call_next):
        start_time = time.time()
        
        # Log request (FastAPI body must be handled carefully)
        self.api_logger.log_request(
            request,
            framework="fastapi"
        )
        
        # Process request
        response = await call_next(request)
        
        # Log response
        self.api_logger.log_response(
            request,
            response,
            framework="fastapi",
            start_time=start_time
        )
        
        return response


# Utility functions for log analysis

class LogAnalyzer:
    """Analyze and query logged API requests."""
    
    def __init__(self, storage: SQLiteLogStorage):
        self.storage = storage
    
    def get_error_rate(self, time_window_hours: int = 1) -> float:
        """Calculate error rate for the given time window."""
        cutoff = (datetime.utcnow() - timedelta(hours=time_window_hours)).isoformat()
        
        with sqlite3.connect(self.storage.db_path) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM api_requests WHERE timestamp > ?",
                (cutoff,)
            ).fetchone()[0]
            
            errors = conn.execute(
                "SELECT COUNT(*) FROM api_requests WHERE timestamp > ? AND response_status >= 400",
                (cutoff,)
            ).fetchone()[0]
        
        return (errors / total * 100) if total > 0 else 0
    
    def get_slow_requests(self, threshold_ms: float = 1000, limit: int = 10) -> List[Dict]:
        """Get slowest requests above threshold."""
        with sqlite3.connect(self.storage.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM api_requests 
                WHERE response_time_ms > ? 
                ORDER BY response_time_ms DESC 
                LIMIT ?
            """, (threshold_ms, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_top_endpoints(self, limit: int = 10) -> List[tuple]:
        """Get most frequently accessed endpoints."""
        with sqlite3.connect(self.storage.db_path) as conn:
            return conn.execute("""
                SELECT endpoint, COUNT(*) as count, 
                       AVG(response_time_ms) as avg_response_time
                FROM api_requests 
                GROUP BY endpoint 
                ORDER BY count DESC 
                LIMIT ?
            """, (limit,)).fetchall()


# Example usage and testing
if __name__ == "__main__":
    # Initialize logger with file storage
    api_logger = APIRequestLogger(
        storage=FileLogStorage(
            log_dir="logs",
            format_type="json",
            compress=True
        ),
        mask_sensitive=True,
        log_request_body=True,
        log_response_body=True,
        sample_rate=1.0
    )
    
    # Flask example
    from flask import Flask, request, jsonify, g
    
    app = Flask(__name__)
    flask_logger = FlaskRequestLogger(api_logger)
    
    @app.route('/api/users', methods=['POST'])
    @flask_logger.log_request_response
    def create_user():
        data = request.get_json()
        # Simulate user creation
        return jsonify({"message": "User created", "user_id": 123}), 201
    
    @app.route('/api/users/<int:user_id>', methods=['GET'])
    @flask_logger.log_request_response
    def get_user(user_id):
        # Simulate user lookup
        return jsonify({"id": user_id, "name": "John Doe"}), 200
    
    # Test with sample requests
    with app.test_client() as client:
        # Test POST request
        client.post('/api/users', 
                   json={"username": "test", "password": "secret123"},
                   headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIs..."})
        
        # Test GET request
        client.get('/api/users/123')
        
        # Test error case
        @app.route('/api/error')
        @flask_logger.log_request_response
        def error_route():
            raise ValueError("Test error")
        
        try:
            client.get('/api/error')
        except:
            pass
    
    print("Logs have been written to the 'logs' directory")