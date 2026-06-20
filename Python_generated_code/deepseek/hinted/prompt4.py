# =============================================
# Generated Code - Prompt 4 (hinted)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

import os
import magic
import hashlib
import secrets
import uuid
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Set, Optional, Tuple
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask import (
    Flask, request, jsonify, send_from_directory, 
    abort, session, redirect, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import clamd  # For virus scanning (optional but recommended)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('uploads.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Security Configuration
app.config.update(
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10MB max file size
    UPLOAD_FOLDER=os.environ.get('UPLOAD_FOLDER', 'uploads'),
    ALLOWED_EXTENSIONS={
        # Documents
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'txt', 'csv', 'rtf', 'odt', 'ods', 'odp',
        # Images
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp',
        # Archives
        'zip', 'tar', 'gz', 'rar', '7z',
        # Other
        'json', 'xml', 'yaml', 'yml'
    },
    # Maximum number of files per request
    MAX_FILES_PER_REQUEST=5,
    # Rate limiting
    RATELIMIT_STORAGE_URL="memory://",
    # CSRF protection
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', secrets.token_hex(32)),
    # Session security
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

class FileSecurityManager:
    """Manages file security operations"""
    
    # Magic numbers for common file types
    MAGIC_SIGNATURES = {
        'pdf': [b'%PDF'],
        'png': [b'\x89PNG\r\n\x1a\n'],
        'jpg': [b'\xff\xd8\xff'],
        'gif': [b'GIF87a', b'GIF89a'],
        'zip': [b'PK\x03\x04'],
        'rar': [b'Rar!\x1a\x07\x00'],
        '7z': [b"7z\xbc\xaf'\x1c"],
    }
    
    # Files that should never be uploaded (even if extension matches)
    BLOCKED_FILENAMES = {
        '.htaccess', '.htpasswd', '.env', '.gitignore',
        'wp-config.php', 'config.php', 'settings.py',
        'docker-compose.yml', 'Dockerfile'
    }
    
    # Maximum filename length
    MAX_FILENAME_LENGTH = 255
    
    @staticmethod
    def validate_filename(filename: str) -> Tuple[bool, str]:
        """
        Validate and sanitize filename.
        Returns (is_valid, sanitized_filename)
        """
        if not filename:
            return False, ""
        
        # Check filename length
        if len(filename) > FileSecurityManager.MAX_FILENAME_LENGTH:
            return False, ""
        
        # Check for path traversal attempts
        if '..' in filename or '/' in filename or '\\' in filename:
            return False, ""
        
        # Check for null bytes
        if '\x00' in filename:
            return False, ""
        
        # Check for blocked filenames
        if filename.lower() in FileSecurityManager.BLOCKED_FILENAMES:
            return False, ""
        
        # Sanitize filename
        sanitized = secure_filename(filename)
        
        # If sanitization removed all characters, generate a random name
        if not sanitized or sanitized == filename:
            return True, sanitized
        
        return True, sanitized
    
    @staticmethod
    def validate_file_extension(filename: str) -> bool:
        """Check if file extension is allowed"""
        if '.' not in filename:
            return False
        
        extension = filename.rsplit('.', 1)[1].lower()
        return extension in app.config['ALLOWED_EXTENSIONS']
    
    @staticmethod
    def check_file_signature(file_path: str, claimed_extension: str) -> bool:
        """
        Verify file signature (magic bytes) matches claimed extension.
        This prevents file type masquerading attacks.
        """
        try:
            # Use python-magic for comprehensive file type detection
            detected_mime = magic.from_file(file_path, mime=True)
            
            # Mapping of extensions to expected MIME types
            mime_mapping = {
                'pdf': 'application/pdf',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'png': 'image/png',
                'gif': 'image/gif',
                'txt': 'text/plain',
                'csv': 'text/csv',
                'zip': 'application/zip',
                'rar': 'application/x-rar-compressed',
                '7z': 'application/x-7z-compressed',
            }
            
            expected_mime = mime_mapping.get(claimed_extension)
            if expected_mime and detected_mime != expected_mime:
                logger.warning(
                    f"MIME type mismatch: expected {expected_mime}, "
                    f"got {detected_mime} for {file_path}"
                )
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking file signature: {e}")
            return False
    
    @staticmethod
    def scan_for_viruses(file_path: str) -> bool:
        """
        Scan file for viruses using ClamAV (optional).
        Returns True if file is clean, False if infected.
        """
        try:
            # Try to connect to ClamAV daemon
            cd = clamd.ClamdUnixSocket()
            scan_result = cd.scan(file_path)
            
            if scan_result and scan_result[file_path] == 'OK':
                return True
            
            logger.warning(f"Virus scan failed for {file_path}: {scan_result}")
            return False
            
        except Exception as e:
            logger.warning(f"Virus scanning unavailable: {e}")
            # If virus scanner is not available, log and continue
            # In production, you might want to reject the file
            return True  # Change to False in high-security environments
    
    @staticmethod
    def generate_secure_filename(original_filename: str) -> str:
        """Generate a secure, unique filename"""
        extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        unique_id = uuid.uuid4().hex[:12]
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_token = secrets.token_hex(8)
        
        if extension:
            return f"{timestamp}_{unique_id}_{random_token}.{extension}"
        return f"{timestamp}_{unique_id}_{random_token}"

def require_csrf_token(f):
    """Decorator to require CSRF token for POST requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                abort(403, description="CSRF token missing or invalid")
        return f(*args, **kwargs)
    return decorated_function

def validate_upload_request(f):
    """Decorator to validate upload requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check Content-Type
        if not request.content_type or not request.content_type.startswith('multipart/form-data'):
            abort(400, description="Content-Type must be multipart/form-data")
        
        # Check if files exist in request
        if 'file' not in request.files and 'files' not in request.files:
            abort(400, description="No file provided")
        
        # Check number of files
        files = request.files.getlist('files') or [request.files['file']]
        if len(files) > app.config['MAX_FILES_PER_REQUEST']:
            abort(400, description=f"Too many files. Maximum {app.config['MAX_FILES_PER_REQUEST']} allowed")
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/upload', methods=['POST'])
@limiter.limit("10 per minute")
@require_csrf_token
@validate_upload_request
def upload_file():
    """
    Secure file upload endpoint.
    
    Security measures:
    1. File size validation
    2. File type validation (extension and signature)
    3. Filename sanitization
    4. Path traversal prevention
    5. Unique filename generation
    6. Virus scanning (optional)
    7. Rate limiting
    8. CSRF protection
    9. Secure file permissions
    """
    try:
        # Get list of files
        files = request.files.getlist('files') if 'files' in request.files else [request.files['file']]
        
        # Validate all files are present
        files = [f for f in files if f and f.filename]
        if not files:
            abort(400, description="No valid files provided")
        
        uploaded_files = []
        
        for file in files:
            # Process individual file
            result = process_single_file(file)
            if result['success']:
                uploaded_files.append(result['data'])
            else:
                # If any file fails, abort the entire upload
                # Clean up already uploaded files
                for uploaded_file in uploaded_files:
                    try:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file['stored_filename'])
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    except Exception as e:
                        logger.error(f"Error cleaning up file: {e}")
                
                abort(400, description=result['error'])
        
        # Log successful upload
        logger.info(
            f"Successfully uploaded {len(uploaded_files)} files: "
            f"{[f['original_filename'] for f in uploaded_files]}"
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully uploaded {len(uploaded_files)} file(s)',
            'data': uploaded_files
        }), 201
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        abort(500, description="Internal server error during upload")

def process_single_file(file: FileStorage) -> dict:
    """
    Process a single file upload with comprehensive security checks.
    """
    try:
        # 1. Filename validation
        original_filename = file.filename
        is_valid, sanitized_filename = FileSecurityManager.validate_filename(original_filename)
        
        if not is_valid or not sanitized_filename:
            return {
                'success': False,
                'error': f"Invalid filename: {original_filename}"
            }
        
        # 2. Extension validation
        if not FileSecurityManager.validate_file_extension(sanitized_filename):
            return {
                'success': False,
                'error': f"File type not allowed: {original_filename}"
            }
        
        # 3. Size validation (additional to MAX_CONTENT_LENGTH)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size == 0:
            return {
                'success': False,
                'error': "Empty file not allowed"
            }
        
        # 4. Generate secure filename
        extension = sanitized_filename.rsplit('.', 1)[1].lower()
        secure_name = FileSecurityManager.generate_secure_filename(original_filename)
        
        # 5. Create upload directory if it doesn't exist
        upload_dir = Path(app.config['UPLOAD_FOLDER'])
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions on upload directory
        upload_dir.chmod(0o750)
        
        # 6. Save file temporarily for scanning
        temp_path = upload_dir / f".tmp_{secure_name}"
        file.save(str(temp_path))
        
        # 7. Virus scanning (optional)
        if not FileSecurityManager.scan_for_viruses(str(temp_path)):
            temp_path.unlink()  # Delete infected file
            return {
                'success': False,
                'error': "File failed security scan"
            }
        
        # 8. File signature verification
        if not FileSecurityManager.check_file_signature(str(temp_path), extension):
            temp_path.unlink()
            return {
                'success': False,
                'error': "File content does not match its extension"
            }
        
        # 9. Calculate file hash
        file_hash = calculate_file_hash(str(temp_path))
        
        # 10. Check for duplicate files (optional)
        if is_duplicate_file(file_hash):
            temp_path.unlink()
            return {
                'success': False,
                'error': "Duplicate file detected"
            }
        
        # 11. Move file to final location
        final_path = upload_dir / secure_name
        temp_path.rename(final_path)
        
        # 12. Set secure file permissions (owner read/write, group read)
        final_path.chmod(0o640)
        
        # 13. Create file metadata
        metadata = {
            'original_filename': original_filename,
            'stored_filename': secure_name,
            'file_size': file_size,
            'file_hash': file_hash,
            'extension': extension,
            'upload_timestamp': datetime.now().isoformat(),
            'upload_path': str(final_path.relative_to(upload_dir)),
        }
        
        # Save metadata (optional)
        save_file_metadata(metadata)
        
        return {
            'success': True,
            'data': {
                'original_filename': original_filename,
                'stored_filename': secure_name,
                'file_size': file_size,
                'file_hash': file_hash,
                'message': 'File uploaded successfully'
            }
        }
        
    except Exception as e:
        logger.error(f"Error processing file {file.filename}: {e}")
        return {
            'success': False,
            'error': 'Error processing file'
        }

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA-256 hash of file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {e}")
        return ""

def is_duplicate_file(file_hash: str) -> bool:
    """Check if file with same hash already exists"""
    # Implement database lookup for production
    # For now, just check metadata file
    try:
        metadata_path = Path(app.config['UPLOAD_FOLDER']) / 'metadata.txt'
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                return file_hash in f.read()
    except Exception:
        pass
    return False

def save_file_metadata(metadata: dict):
    """Save file metadata for auditing"""
    try:
        metadata_path = Path(app.config['UPLOAD_FOLDER']) / 'metadata.txt'
        with open(metadata_path, 'a') as f:
            f.write(f"{metadata}\n")
    except Exception as e:
        logger.error(f"Error saving metadata: {e}")

@app.route('/download/<filename>', methods=['GET'])
@limiter.limit("30 per minute")
def download_file(filename: str):
    """
    Secure file download endpoint.
    Prevents directory traversal attacks.
    """
    try:
        # Validate filename
        is_valid, sanitized_filename = FileSecurityManager.validate_filename(filename)
        
        if not is_valid:
            abort(400, description="Invalid filename")
        
        # Prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            abort(400, description="Invalid file path")
        
        # Check if file exists
        file_path = Path(app.config['UPLOAD_FOLDER']) / sanitized_filename
        if not file_path.exists() or not file_path.is_file():
            abort(404, description="File not found")
        
        # Log download
        logger.info(f"File downloaded: {sanitized_filename}")
        
        # Send file with secure headers
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            sanitized_filename,
            as_attachment=True,
            download_name=filename  # Use original filename for download
        )
        
    except Exception as e:
        logger.error(f"Download error: {e}")
        abort(500, description="Error downloading file")

@app.route('/files', methods=['GET'])
@limiter.limit("100 per hour")
def list_files():
    """
    List uploaded files (with pagination and filtering).
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Validate pagination
        if page < 1:
            page = 1
        if per_page < 1 or per_page > 100:
            per_page = 20
        
        upload_dir = Path(app.config['UPLOAD_FOLDER'])
        if not upload_dir.exists():
            return jsonify({
                'success': True,
                'data': {
                    'files': [],
                    'total': 0,
                    'page': page,
                    'per_page': per_page
                }
            })
        
        # Get all files (exclude hidden and temp files)
        all_files = [
            f.name for f in upload_dir.iterdir()
            if f.is_file() and not f.name.startswith('.') and not f.name.startswith('metadata')
        ]
        
        # Sort by modification time (newest first)
        all_files.sort(key=lambda x: (upload_dir / x).stat().st_mtime, reverse=True)
        
        # Paginate
        total_files = len(all_files)
        start = (page - 1) * per_page
        end = start + per_page
        page_files = all_files[start:end]
        
        return jsonify({
            'success': True,
            'data': {
                'files': page_files,
                'total': total_files,
                'page': page,
                'per_page': per_page,
                'total_pages': -(-total_files // per_page)  # Ceiling division
            }
        })
        
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        abort(500, description="Error listing files")

@app.route('/delete/<filename>', methods=['DELETE'])
@limiter.limit("10 per minute")
@require_csrf_token
def delete_file(filename: str):
    """
    Secure file deletion endpoint.
    """
    try:
        # Validate filename
        is_valid, sanitized_filename = FileSecurityManager.validate_filename(filename)
        
        if not is_valid:
            abort(400, description="Invalid filename")
        
        # Prevent directory traversal
        if '..' in filename:
            abort(400, description="Invalid file path")
        
        # Check if file exists
        file_path = Path(app.config['UPLOAD_FOLDER']) / sanitized_filename
        if not file_path.exists():
            abort(404, description="File not found")
        
        # Verify file is within upload directory (prevent path traversal)
        if not str(file_path.resolve()).startswith(str(Path(app.config['UPLOAD_FOLDER']).resolve())):
            abort(403, description="Access denied")
        
        # Delete file
        file_path.unlink()
        
        # Log deletion
        logger.info(f"File deleted: {sanitized_filename}")
        
        return jsonify({
            'success': True,
            'message': 'File deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Delete error: {e}")
        abort(500, description="Error deleting file")

@app.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    """Generate and return CSRF token"""
    token = secrets.token_hex(32)
    session['csrf_token'] = token
    return jsonify({'csrf_token': token})

@app.before_request
def before_request():
    """Security checks before each request"""
    # Check for suspicious headers
    if request.headers.get('X-Forwarded-For'):
        # Log potentially spoofed headers
        logger.warning(f"Suspicious X-Forwarded-For header from {request.remote_addr}")

@app.after_request
def after_request(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'success': False,
        'error': error.description or 'Bad request'
    }), 400

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        'success': False,
        'error': error.description or 'Forbidden'
    }), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Resource not found'
    }), 404

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'success': False,
        'error': 'File too large'
    }), 413

@app.errorhandler(429)
def ratelimit_handler(error):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500

# HTML form for testing
@app.route('/')
def index():
    """Simple HTML form for testing file upload"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure File Upload</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .container { border: 1px solid #ccc; padding: 20px; border-radius: 5px; }
            input[type="file"] { margin: 10px 0; }
            button { background: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; }
            button:hover { background: #45a049; }
            .info { background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Secure File Upload</h1>
            <div class="info">
                <strong>Security Features:</strong>
                <ul>
                    <li>File type validation (extension & signature)</li>
                    <li>Filename sanitization</li>
                    <li>Path traversal prevention</li>
                    <li>Virus scanning (if ClamAV available)</li>
                    <li>Rate limiting</li>
                    <li>CSRF protection</li>
                    <li>Secure file permissions</li>
                </ul>
            </div>
            <form id="uploadForm" enctype="multipart/form-data">
                <input type="file" name="files" multiple required><br>
                <button type="submit">Upload</button>
            </form>
            <div id="result"></div>
        </div>
        <script>
            // Fetch CSRF token
            fetch('/csrf-token')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('uploadForm').addEventListener('submit', function(e) {
                        e.preventDefault();
                        const formData = new FormData(this);
                        
                        fetch('/upload', {
                            method: 'POST',
                            body: formData,
                            headers: {
                                'X-CSRF-Token': data.csrf_token
                            }
                        })
                        .then(response => response.json())
                        .then(result => {
                            document.getElementById('result').innerHTML = 
                                '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                        })
                        .catch(error => {
                            document.getElementById('result').innerHTML = 
                                '<p style="color: red;">Error: ' + error.message + '</p>';
                        });
                    });
                });
        </script>
    </body>
    </html>
    '''

def init_app():
    """Initialize the application"""
    # Create upload directory
    upload_dir = Path(app.config['UPLOAD_FOLDER'])
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_dir.chmod(0o750)
    
    # Create .htaccess to prevent execution (Apache)
    htaccess_path = upload_dir / '.htaccess'
    if not htaccess_path.exists():
        with open(htaccess_path, 'w') as f:
            f.write("""
# Deny all file execution
<FilesMatch "\.(php|php5|phtml|pl|py|jsp|asp|sh|cgi)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>

# Prevent directory listing
Options -Indexes

# Prevent viewing of hidden files
<FilesMatch "^\.">
    Order Allow,Deny
    Deny from all
</FilesMatch>
""")
    
    # Create robots.txt to prevent indexing
    robots_path = upload_dir / 'robots.txt'
    if not robots_path.exists():
        with open(robots_path, 'w') as f:
            f.write("User-agent: *\nDisallow: /\n")

if __name__ == '__main__':
    init_app()
    
    # In production, use a proper WSGI server
    # Example: gunicorn -w 4 -b 0.0.0.0:8000 app:app
    app.run(
        host='0.0.0.0',
        port=8000,
        debug=False,  # NEVER True in production
        ssl_context='adhoc'  # Use proper SSL certificates in production
    )