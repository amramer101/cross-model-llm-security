# =============================================
# Generated Code - Prompt 4 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import os
import re
import uuid
import magic
import hashlib
import secrets
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Set, Tuple, List
from functools import wraps
from collections import defaultdict
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask import Flask, request, jsonify, render_template_string, send_from_directory, g

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max request size

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
    """Centralized security configuration for file uploads."""
    
    # Directory configuration
    UPLOAD_FOLDER = Path(os.environ.get('UPLOAD_FOLDER', 'uploads'))
    TEMP_FOLDER = Path(os.environ.get('TEMP_FOLDER', 'temp_uploads'))
    QUARANTINE_FOLDER = Path(os.environ.get('QUARANTINE_FOLDER', 'quarantine'))
    
    # File size limits
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB per file
    MAX_TOTAL_UPLOAD_SIZE = 20 * 1024 * 1024  # 20MB total per request
    
    # Allowed file types (MIME types and extensions)
    ALLOWED_MIMETYPES = {
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'application/pdf',
        'text/plain',
        'text/csv',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/zip',
        'application/x-zip-compressed'
    }
    
    ALLOWED_EXTENSIONS = {
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'csv',
        'doc', 'docx', 'xls', 'xlsx', 'zip'
    }
    
    # Blocked extensions (even if MIME type is allowed)
    BLOCKED_EXTENSIONS = {
        'exe', 'dll', 'so', 'sh', 'bash', 'zsh', 'csh', 'fish',
        'bat', 'cmd', 'ps1', 'vbs', 'js', 'php', 'pl', 'py', 'rb',
        'jar', 'war', 'ear', 'class', 'msi', 'apk', 'ipa'
    }
    
    # File name constraints
    MAX_FILENAME_LENGTH = 255
    ALLOWED_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$')
    
    # Rate limiting
    UPLOAD_RATE_LIMIT = 10  # requests per window
    UPLOAD_RATE_WINDOW = 3600  # 1 hour in seconds
    
    # Anti-virus (mock configuration - use ClamAV in production)
    ENABLE_VIRUS_SCAN = os.environ.get('ENABLE_VIRUS_SCAN', 'false').lower() == 'true'
    
    # File retention
    MAX_FILE_AGE_DAYS = 30
    MAX_FILES_PER_USER = 100

# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimiter:
    """In-memory rate limiter (use Redis in production)."""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = __import__('threading').Lock()
    
    def is_allowed(self, identifier: str, max_requests: int, window_seconds: int) -> bool:
        """Check if request is within rate limits."""
        with self.lock:
            now = datetime.now()
            window_start = now - timedelta(seconds=window_seconds)
            
            # Clean old requests
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > window_start
            ]
            
            # Check limit
            if len(self.requests[identifier]) >= max_requests:
                return False
            
            # Record request
            self.requests[identifier].append(now)
            return True
    
    def get_remaining(self, identifier: str, max_requests: int, window_seconds: int) -> int:
        """Get remaining requests for current window."""
        with self.lock:
            now = datetime.now()
            window_start = now - timedelta(seconds=window_seconds)
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if req_time > window_start
            ]
            return max(0, max_requests - len(self.requests[identifier]))

rate_limiter = RateLimiter()

# ============================================================================
# File Validation and Security
# ============================================================================

class FileValidator:
    """Handles file validation and security checks."""
    
    @staticmethod
    def validate_file_size(file: FileStorage) -> bool:
        """Validate file size is within limits."""
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        
        if size > SecurityConfig.MAX_FILE_SIZE:
            return False
        if size == 0:
            return False
        return True
    
    @staticmethod
    def validate_file_extension(filename: str) -> Tuple[bool, str]:
        """
        Validate file extension using whitelist approach.
        Returns (is_valid, extension).
        """
        if '.' not in filename:
            return False, ''
        
        extension = filename.rsplit('.', 1)[1].lower()
        
        # Check against blocked extensions first
        if extension in SecurityConfig.BLOCKED_EXTENSIONS:
            return False, extension
        
        # Check against allowed extensions
        if extension not in SecurityConfig.ALLOWED_EXTENSIONS:
            return False, extension
        
        return True, extension
    
    @staticmethod
    def validate_mime_type(file: FileStorage) -> Tuple[bool, str, str]:
        """
        Validate file MIME type using magic numbers.
        Returns (is_valid, detected_type, file_signature).
        """
        try:
            # Save current position
            current_pos = file.tell()
            file.seek(0)
            
            # Read first 2048 bytes for MIME detection
            file_header = file.read(2048)
            file.seek(current_pos)
            
            # Use python-magic to detect actual MIME type from content
            detected_mime = magic.from_buffer(file_header, mime=True)
            
            # Get file signature (magic bytes)
            signature = file_header[:8].hex()
            
            # Check against allowed MIME types
            if detected_mime not in SecurityConfig.ALLOWED_MIMETYPES:
                return False, detected_mime, signature
            
            return True, detected_mime, signature
            
        except Exception as e:
            logger.error(f"Error detecting MIME type: {str(e)}")
            return False, 'unknown', ''
    
    @staticmethod
    def validate_filename(filename: str) -> Tuple[bool, str]:
        """
        Validate and sanitize filename.
        Returns (is_valid, sanitized_filename).
        """
        # Check length
        if len(filename) > SecurityConfig.MAX_FILENAME_LENGTH:
            return False, ''
        
        # Check for path traversal attempts
        if '..' in filename or '/' in filename or '\\' in filename:
            return False, ''
        
        # Check for null bytes
        if '\x00' in filename:
            return False, ''
        
        # Check filename pattern
        name_without_ext = filename.rsplit('.', 1)[0] if '.' in filename else filename
        if not SecurityConfig.ALLOWED_FILENAME_PATTERN.match(name_without_ext):
            return False, ''
        
        # Use werkzeug's secure_filename as additional safety
        sanitized = secure_filename(filename)
        if not sanitized:
            return False, ''
        
        # Ensure sanitized filename still has an extension
        if '.' not in sanitized:
            return False, ''
        
        return True, sanitized
    
    @staticmethod
    def check_for_malicious_content(file: FileStorage) -> Tuple[bool, str]:
        """
        Scan file for malicious content patterns.
        Returns (is_safe, reason).
        """
        try:
            current_pos = file.tell()
            file.seek(0)
            
            # Read file content for scanning
            content = file.read(SecurityConfig.MAX_FILE_SIZE)
            file.seek(current_pos)
            
            # Check for common malicious patterns
            malicious_patterns = [
                (b'<?php', 'PHP code detected'),
                (b'<script', 'Script tag detected'),
                (b'eval(', 'Eval function detected'),
                (b'exec(', 'Exec function detected'),
                (b'system(', 'System call detected'),
                (b'base64_decode', 'Base64 decode detected'),
                (b'#!/', 'Shebang detected'),
                (b'import os', 'Python OS import detected'),
                (b'cmd.exe', 'Windows command detected'),
                (b'/bin/bash', 'Bash reference detected'),
                (b'<?=', 'PHP short tag detected'),
            ]
            
            for pattern, reason in malicious_patterns:
                if pattern in content.lower():
                    return False, reason
            
            # Check for embedded files in archives (simplified check)
            if b'PK' in content[:4] and content.lower().count(b'.exe') > 0:
                return False, 'Executable in archive detected'
            
            return True, 'Clean'
            
        except Exception as e:
            logger.error(f"Error scanning file: {str(e)}")
            return False, 'Scan error'

# ============================================================================
# File Storage and Management
# ============================================================================

class FileManager:
    """Manages secure file storage and retrieval."""
    
    @staticmethod
    def create_secure_directory(directory: Path) -> None:
        """Create directory with secure permissions."""
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o750)  # rwxr-x---
    
    @staticmethod
    def generate_secure_filename(original_filename: str, user_id: str) -> str:
        """Generate a secure, unique filename."""
        # Extract extension
        extension = original_filename.rsplit('.', 1)[1].lower()
        
        # Generate unique identifier
        unique_id = uuid.uuid4().hex[:12]
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        # Create hash of original filename
        name_hash = hashlib.sha256(
            f"{original_filename}{user_id}{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
        
        # Combine to create secure filename
        secure_name = f"{timestamp}_{user_id}_{unique_id}_{name_hash}.{extension}"
        
        return secure_name
    
    @staticmethod
    def save_file(file: FileStorage, filename: str, upload_dir: Path) -> Path:
        """Save file securely to disk."""
        file_path = upload_dir / filename
        
        # Ensure we're still within the upload directory (prevent path traversal)
        file_path = file_path.resolve()
        if not str(file_path).startswith(str(upload_dir.resolve())):
            raise ValueError("Invalid file path detected")
        
        # Save file with secure permissions
        file.save(str(file_path))
        os.chmod(file_path, 0o640)  # rw-r-----
        
        return file_path
    
    @staticmethod
    def get_file_hash(file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def check_user_file_limit(user_upload_dir: Path, max_files: int) -> bool:
        """Check if user has exceeded file limit."""
        if not user_upload_dir.exists():
            return True
        
        file_count = len(list(user_upload_dir.glob('*')))
        return file_count < max_files

# ============================================================================
# Authentication and Authorization
# ============================================================================

class AuthManager:
    """Manages authentication (mock implementation)."""
    
    @staticmethod
    def validate_api_key(api_key: str) -> Optional[str]:
        """
        Validate API key and return user_id.
        In production, use proper authentication (JWT, OAuth2, etc.).
        """
        # Mock API keys (use database in production)
        valid_keys = {
            'sk_test_user1_key_123': 'user_123',
            'sk_test_user2_key_456': 'user_456',
            'sk_admin_key_789': 'admin_789'
        }
        
        return valid_keys.get(api_key)
    
    @staticmethod
    def validate_csrf_token(user_id: str, csrf_token: str) -> bool:
        """
        Validate CSRF token.
        In production, use Flask-WTF or similar.
        """
        # Mock CSRF validation (use session-based tokens in production)
        expected_token = hashlib.sha256(
            f"{user_id}{app.config['SECRET_KEY']}".encode()
        ).hexdigest()[:32]
        
        return secrets.compare_digest(csrf_token, expected_token)

# ============================================================================
# Decorators
# ============================================================================

def require_auth(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.form.get('api_key')
        
        if not api_key:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'API key is required'
            }), 401
        
        user_id = AuthManager.validate_api_key(api_key)
        if not user_id:
            # Use constant-time comparison to prevent timing attacks
            dummy_key = secrets.token_hex(16)
            secrets.compare_digest(api_key or '', dummy_key)
            
            logger.warning(f"Invalid API key attempt from IP: {request.remote_addr}")
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid API key'
            }), 401
        
        # Store user_id for the request
        g.user_id = user_id
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_upload(f):
    """Decorator to rate limit upload endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        identifier = f"upload:{request.remote_addr}"
        
        if not rate_limiter.is_allowed(
            identifier,
            SecurityConfig.UPLOAD_RATE_LIMIT,
            SecurityConfig.UPLOAD_RATE_WINDOW
        ):
            logger.warning(f"Upload rate limit exceeded for IP: {request.remote_addr}")
            return jsonify({
                'error': 'Too Many Requests',
                'message': 'Upload rate limit exceeded. Please try again later.',
                'retry_after': SecurityConfig.UPLOAD_RATE_WINDOW
            }), 429
        
        # Add rate limit headers
        remaining = rate_limiter.get_remaining(
            identifier,
            SecurityConfig.UPLOAD_RATE_LIMIT,
            SecurityConfig.UPLOAD_RATE_WINDOW
        )
        
        response = f(*args, **kwargs)
        
        if isinstance(response, tuple):
            response_obj, status_code = response
        else:
            response_obj, status_code = response, 200
        
        if hasattr(response_obj, 'headers'):
            response_obj.headers['X-RateLimit-Limit'] = str(SecurityConfig.UPLOAD_RATE_LIMIT)
            response_obj.headers['X-RateLimit-Remaining'] = str(remaining)
        
        return response_obj, status_code
    return decorated_function

# ============================================================================
# Initialize Storage Directories
# ============================================================================

def init_directories():
    """Initialize upload directories with secure permissions."""
    directories = [
        SecurityConfig.UPLOAD_FOLDER,
        SecurityConfig.TEMP_FOLDER,
        SecurityConfig.QUARANTINE_FOLDER
    ]
    
    for directory in directories:
        FileManager.create_secure_directory(directory)
        # Create .htaccess to prevent execution (for Apache)
        htaccess_path = directory / '.htaccess'
        if not htaccess_path.exists():
            with open(htaccess_path, 'w') as f:
                f.write("php_flag engine off\n")
                f.write("RemoveHandler .php .phtml .php3 .php4 .php5 .php7\n")
                f.write("RemoveType .php .phtml .php3 .php4 .php5 .php7\n")
                f.write("<FilesMatch \"\.(php|phtml|php3|php4|php5|php7|phar|pl|py|cgi|sh|bash|exe|dll|so|bin|cmd|bat|ps1)$\">\n")
                f.write("    Order Deny,Allow\n")
                f.write("    Deny from all\n")
                f.write("</FilesMatch>\n")
            os.chmod(htaccess_path, 0o640)

# ============================================================================
# Routes
# ============================================================================

@app.route('/upload', methods=['POST'])
@require_auth
@rate_limit_upload
def upload_file():
    """
    Secure file upload endpoint.
    
    Accepts multipart/form-data with:
    - file: The file to upload
    - csrf_token: CSRF protection token
    
    Headers:
    - X-API-Key: Authentication key
    
    Returns JSON with upload details.
    """
    
    try:
        # Validate CSRF token
        csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not csrf_token or not AuthManager.validate_csrf_token(g.user_id, csrf_token):
            logger.warning(f"CSRF validation failed for user: {g.user_id}")
            return jsonify({
                'error': 'Forbidden',
                'message': 'CSRF validation failed'
            }), 403
        
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({
                'error': 'Bad Request',
                'message': 'No file provided'
            }), 400
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '' or file.filename is None:
            return jsonify({
                'error': 'Bad Request',
                'message': 'No file selected'
            }), 400
        
        # Create user-specific upload directory
        user_upload_dir = SecurityConfig.UPLOAD_FOLDER / g.user_id
        FileManager.create_secure_directory(user_upload_dir)
        
        # Check user file limit
        if not FileManager.check_user_file_limit(user_upload_dir, SecurityConfig.MAX_FILES_PER_USER):
            return jsonify({
                'error': 'Forbidden',
                'message': f'File limit reached. Maximum {SecurityConfig.MAX_FILES_PER_USER} files allowed.'
            }), 403
        
        # Validate file size
        if not FileValidator.validate_file_size(file):
            return jsonify({
                'error': 'Bad Request',
                'message': f'File size must be between 1 byte and {SecurityConfig.MAX_FILE_SIZE // (1024*1024)}MB'
            }), 400
        
        # Validate file extension
        ext_valid, extension = FileValidator.validate_file_extension(file.filename)
        if not ext_valid:
            logger.warning(f"Blocked file extension: {extension} from user: {g.user_id}")
            return jsonify({
                'error': 'Bad Request',
                'message': f'File type not allowed'
            }), 400
        
        # Validate MIME type
        mime_valid, detected_mime, signature = FileValidator.validate_mime_type(file)
        if not mime_valid:
            logger.warning(f"Blocked MIME type: {detected_mime} from user: {g.user_id}")
            # Quarantine suspicious file
            quarantine_path = SecurityConfig.QUARANTINE_FOLDER / f"suspicious_{uuid.uuid4().hex[:8]}.bin"
            file.seek(0)
            file.save(str(quarantine_path))
            
            return jsonify({
                'error': 'Bad Request',
                'message': 'File type not allowed'
            }), 400
        
        # Validate filename
        name_valid, sanitized_filename = FileValidator.validate_filename(file.filename)
        if not name_valid:
            return jsonify({
                'error': 'Bad Request',
                'message': 'Invalid filename'
            }), 400
        
        # Scan for malicious content
        is_safe, scan_result = FileValidator.check_for_malicious_content(file)
        if not is_safe:
            logger.warning(f"Malicious content detected: {scan_result} from user: {g.user_id}")
            # Quarantine malicious file
            quarantine_path = SecurityConfig.QUARANTINE_FOLDER / f"malicious_{uuid.uuid4().hex[:8]}.bin"
            file.seek(0)
            file.save(str(quarantine_path))
            
            return jsonify({
                'error': 'Bad Request',
                'message': 'File content not allowed'
            }), 400
        
        # Generate secure filename
        secure_filename = FileManager.generate_secure_filename(sanitized_filename, g.user_id)
        
        # Reset file pointer before saving
        file.seek(0)
        
        # Save file to user's directory
        file_path = FileManager.save_file(file, secure_filename, user_upload_dir)
        
        # Calculate file hash
        file_hash = FileManager.get_file_hash(file_path)
        
        # Get file size
        file_size = file_path.stat().st_size
        
        # Log successful upload
        logger.info(
            f"File uploaded successfully - "
            f"User: {g.user_id}, "
            f"Original: {file.filename}, "
            f"Saved: {secure_filename}, "
            f"Size: {file_size} bytes, "
            f"Hash: {file_hash}, "
            f"Type: {detected_mime}"
        )
        
        return jsonify({
            'success': True,
            'data': {
                'file_id': secure_filename,
                'original_filename': sanitized_filename,
                'file_size': file_size,
                'mime_type': detected_mime,
                'extension': extension,
                'upload_timestamp': datetime.utcnow().isoformat() + 'Z',
                'file_hash': file_hash,
                'download_url': f'/download/{secure_filename}'
            },
            'message': 'File uploaded successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred during upload'
        }), 500

@app.route('/download/<filename>', methods=['GET'])
@require_auth
def download_file(filename: str):
    """
    Secure file download endpoint.
    
    Args:
        filename: The secure filename to download
    """
    try:
        # Validate filename format
        if not SecurityConfig.ALLOWED_FILENAME_PATTERN.match(filename.rsplit('.', 1)[0]):
            return jsonify({
                'error': 'Bad Request',
                'message': 'Invalid filename'
            }), 400
        
        # Construct user's upload directory
        user_upload_dir = SecurityConfig.UPLOAD_FOLDER / g.user_id
        
        # Verify file exists
        file_path = user_upload_dir / filename
        if not file_path.exists() or not file_path.is_file():
            # Add delay to prevent user enumeration
            __import__('time').sleep(0.5)
            return jsonify({
                'error': 'Not Found',
                'message': 'File not found'
            }), 404
        
        # Verify file is within allowed directory (prevent path traversal)
        file_path = file_path.resolve()
        if not str(file_path).startswith(str(user_upload_dir.resolve())):
            logger.error(f"Path traversal attempt: {filename} by user: {g.user_id}")
            return jsonify({
                'error': 'Forbidden',
                'message': 'Access denied'
            }), 403
        
        # Log download
        logger.info(f"File download: {filename} by user: {g.user_id}")
        
        return send_from_directory(
            str(user_upload_dir),
            filename,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Download error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500

@app.route('/upload/multiple', methods=['POST'])
@require_auth
@rate_limit_upload
def upload_multiple_files():
    """
    Upload multiple files securely.
    
    Accepts multipart/form-data with:
    - files: Multiple files to upload
    - csrf_token: CSRF protection token
    
    Headers:
    - X-API-Key: Authentication key
    """
    
    try:
        # Validate CSRF token
        csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not csrf_token or not AuthManager.validate_csrf_token(g.user_id, csrf_token):
            return jsonify({
                'error': 'Forbidden',
                'message': 'CSRF validation failed'
            }), 403
        
        # Check if files are present
        if 'files' not in request.files:
            return jsonify({
                'error': 'Bad Request',
                'message': 'No files provided'
            }), 400
        
        files = request.files.getlist('files')
        
        # Check number of files
        if len(files) > 10:  # Maximum 10 files per request
            return jsonify({
                'error': 'Bad Request',
                'message': 'Maximum 10 files per request'
            }), 400
        
        if len(files) == 0:
            return jsonify({
                'error': 'Bad Request',
                'message': 'No files selected'
            }), 400
        
        # Create user-specific upload directory
        user_upload_dir = SecurityConfig.UPLOAD_FOLDER / g.user_id
        FileManager.create_secure_directory(user_upload_dir)
        
        # Calculate total upload size
        total_size = sum(len(file.read()) for file in files)
        for file in files:
            file.seek(0)
        
        if total_size > SecurityConfig.MAX_TOTAL_UPLOAD_SIZE:
            return jsonify({
                'error': 'Bad Request',
                'message': f'Total upload size exceeds {SecurityConfig.MAX_TOTAL_UPLOAD_SIZE // (1024*1024)}MB limit'
            }), 400
        
        # Process each file
        uploaded_files = []
        errors = []
        
        for i, file in enumerate(files):
            try:
                # Validate file size
                if not FileValidator.validate_file_size(file):
                    errors.append({
                        'index': i,
                        'filename': file.filename,
                        'error': 'File size exceeds limit'
                    })
                    continue
                
                # Validate extension
                ext_valid, extension = FileValidator.validate_file_extension(file.filename)
                if not ext_valid:
                    errors.append({
                        'index': i,
                        'filename': file.filename,
                        'error': 'File type not allowed'
                    })
                    continue
                
                # Validate MIME type
                mime_valid, detected_mime, _ = FileValidator.validate_mime_type(file)
                if not mime_valid:
                    errors.append({
                        'index': i,
                        'filename': file.filename,
                        'error': 'File type not allowed'
                    })
                    continue
                
                # Validate filename
                name_valid, sanitized = FileValidator.validate_filename(file.filename)
                if not name_valid:
                    errors.append({
                        'index': i,
                        'filename': file.filename,
                        'error': 'Invalid filename'
                    })
                    continue
                
                # Generate secure filename
                secure_name = FileManager.generate_secure_filename(sanitized, g.user_id)
                
                # Save file
                file.seek(0)
                file_path = FileManager.save_file(file, secure_name, user_upload_dir)
                
                # Get file info
                file_hash = FileManager.get_file_hash(file_path)
                file_size = file_path.stat().st_size
                
                uploaded_files.append({
                    'original_filename': sanitized,
                    'saved_filename': secure_name,
                    'file_size': file_size,
                    'mime_type': detected_mime,
                    'file_hash': file_hash
                })
                
                logger.info(f"File {i+1} uploaded: {sanitized} -> {secure_name}")
                
            except Exception as e:
                logger.error(f"Error processing file {i}: {str(e)}")
                errors.append({
                    'index': i,
                    'filename': file.filename if file.filename else 'unknown',
                    'error': 'Processing error'
                })
        
        return jsonify({
            'success': True,
            'data': {
                'uploaded_files': uploaded_files,
                'errors': errors,
                'total_uploaded': len(uploaded_files),
                'total_errors': len(errors)
            },
            'message': f'Uploaded {len(uploaded_files)} of {len(files)} files'
        }), 201
        
    except Exception as e:
        logger.error(f"Multiple upload error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500

# HTML upload form for testing
@app.route('/upload/form', methods=['GET'])
def upload_form():
    """Simple HTML form for testing file uploads."""
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure File Upload</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
                .form-group { margin-bottom: 15px; }
                label { display: block; margin-bottom: 5px; font-weight: bold; }
                input[type="file"], input[type="text"] { width: 100%; padding: 8px; }
                button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
                button:hover { background: #0056b3; }
                .info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <h1>Secure File Upload</h1>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="api_key">API Key:</label>
                    <input type="text" id="api_key" name="api_key" required 
                           placeholder="Enter your API key">
                </div>
                <div class="form-group">
                    <label for="csrf_token">CSRF Token:</label>
                    <input type="text" id="csrf_token" name="csrf_token" required 
                           placeholder="Enter CSRF token">
                </div>
                <div class="form-group">
                    <label for="file">Select File:</label>
                    <input type="file" id="file" name="file" required>
                </div>
                <button type="submit">Upload File</button>
            </form>
            
            <div class="info">
                <h3>Security Features:</h3>
                <ul>
                    <li>File type validation (MIME and extension)</li>
                    <li>Malicious content scanning</li>
                    <li>Rate limiting</li>
                    <li>CSRF protection</li>
                    <li>Secure filename generation</li>
                    <li>Path traversal prevention</li>
                </ul>
            </div>
        </body>
        </html>
    ''')

# Error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'error': 'Payload Too Large',
        'message': f'Request size exceeds maximum limit of {app.config["MAX_CONTENT_LENGTH"] // (1024*1024)}MB'
    }), 413

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested resource was not found'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred'
    }), 500

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ============================================================================
# Main Application
# ============================================================================

if __name__ == '__main__':
    # Initialize directories
    init_directories()
    
    # Run the application
    # In production, use Gunicorn with HTTPS:
    # gunicorn -w 4 -b 0.0.0.0:8000 --certfile=cert.pem --keyfile=key.pem app:app
    app.run(
        debug=False,
        host='0.0.0.0',
        port=8000,
        ssl_context='adhoc'  # Enable HTTPS (use proper certs in production)
    )