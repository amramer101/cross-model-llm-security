# =============================================
# Generated Code - Prompt 4 (naive)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import (
    Flask, request, render_template_string, 
    jsonify, send_from_directory, redirect, 
    url_for, flash, session
)
import magic  # python-magic for MIME type detection
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for flash messages

# Configuration
UPLOAD_FOLDER = Path('uploads')
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 
    'doc', 'docx', 'xls', 'xlsx', 'csv', 
    'zip', 'rar', 'mp4', 'mp3', 'wav'
}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB
MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB for Flask

app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS

# Ensure upload directory exists
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

# Create subdirectories for organization
for subdir in ['images', 'documents', 'archives', 'media', 'other']:
    (UPLOAD_FOLDER / subdir).mkdir(exist_ok=True)


def allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_category(filename: str) -> str:
    """Determine file category based on extension."""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    image_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp'}
    document_extensions = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv'}
    archive_extensions = {'zip', 'rar', '7z', 'tar', 'gz'}
    media_extensions = {'mp4', 'mp3', 'wav', 'avi', 'mov', 'flv', 'wmv'}
    
    if ext in image_extensions:
        return 'images'
    elif ext in document_extensions:
        return 'documents'
    elif ext in archive_extensions:
        return 'archives'
    elif ext in media_extensions:
        return 'media'
    else:
        return 'other'


def generate_safe_filename(original_filename: str) -> str:
    """
    Generate a safe, unique filename while preserving extension.
    Format: timestamp_uuid_originalname
    """
    # Secure the filename (remove dangerous characters)
    filename = secure_filename(original_filename)
    
    # Split name and extension
    name, ext = os.path.splitext(filename)
    
    # Generate unique name with timestamp and UUID
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = str(uuid.uuid4())[:8]
    
    # Create safe filename
    safe_name = f"{timestamp}_{unique_id}_{name}{ext}"
    
    return safe_name


def validate_file_mime_type(file) -> bool:
    """
    Validate file MIME type using python-magic.
    Prevents MIME type spoofing.
    """
    try:
        # Read first 2048 bytes for MIME detection
        file_start = file.read(2048)
        file.seek(0)  # Reset file pointer
        
        mime = magic.Magic(mime=True)
        detected_mime = mime.from_buffer(file_start)
        
        # List of allowed MIME types
        allowed_mimes = [
            'text/plain', 'application/pdf',
            'image/png', 'image/jpeg', 'image/gif',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/zip', 'application/x-rar-compressed',
            'video/mp4', 'audio/mpeg', 'audio/wav'
        ]
        
        return detected_mime in allowed_mimes
    except Exception:
        return False


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# HTML Templates
UPLOAD_FORM_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 600px;
            width: 100%;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 2em;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        
        .upload-area {
            border: 3px dashed #ccc;
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            transition: all 0.3s ease;
            background: #f9f9f9;
            cursor: pointer;
            margin-bottom: 20px;
        }
        
        .upload-area:hover, .upload-area.dragover {
            border-color: #667eea;
            background: #f0f0ff;
        }
        
        .upload-area i {
            font-size: 48px;
            color: #667eea;
            margin-bottom: 15px;
        }
        
        .file-input {
            display: none;
        }
        
        .upload-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 16px;
            cursor: pointer;
            transition: transform 0.2s;
            width: 100%;
        }
        
        .upload-btn:hover {
            transform: translateY(-2px);
        }
        
        .upload-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .file-list {
            margin-top: 20px;
        }
        
        .file-item {
            display: flex;
            align-items: center;
            padding: 10px;
            background: #f5f5f5;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        
        .file-item .file-name {
            flex: 1;
            margin-left: 10px;
        }
        
        .file-item .file-size {
            color: #666;
            font-size: 0.9em;
        }
        
        .progress-bar {
            width: 100%;
            height: 5px;
            background: #e0e0e0;
            border-radius: 3px;
            margin-top: 10px;
            overflow: hidden;
            display: none;
        }
        
        .progress-bar .progress {
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.3s;
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        
        .info-box {
            background: #f0f8ff;
            border-left: 4px solid #667eea;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .info-box ul {
            margin-left: 20px;
            margin-top: 5px;
        }
        
        .info-box li {
            color: #666;
            margin-bottom: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 File Upload</h1>
        <p class="subtitle">Upload your files securely</p>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="info-box">
            <strong>Allowed file types:</strong>
            <ul>
                <li>Images: png, jpg, jpeg, gif</li>
                <li>Documents: pdf, doc, docx, xls, xlsx, txt, csv</li>
                <li>Archives: zip, rar</li>
                <li>Media: mp4, mp3, wav</li>
            </ul>
            <p style="margin-top: 5px; color: #666;">
                <strong>Max file size:</strong> 16 MB
            </p>
        </div>
        
        <form id="upload-form" method="POST" enctype="multipart/form-data">
            <div class="upload-area" id="upload-area">
                <div>📤</div>
                <p style="margin-top: 10px; color: #666;">
                    Drag & drop files here or click to browse
                </p>
                <input type="file" name="file" id="file-input" class="file-input" 
                       accept=".txt,.pdf,.png,.jpg,.jpeg,.gif,.doc,.docx,.xls,.xlsx,.csv,.zip,.rar,.mp4,.mp3,.wav"
                       required>
            </div>
            
            <div class="file-list" id="file-list"></div>
            <div class="progress-bar" id="progress-bar">
                <div class="progress" id="progress"></div>
            </div>
            
            <button type="submit" class="upload-btn" id="upload-btn">
                Upload File
            </button>
        </form>
        
        <div style="margin-top: 20px; text-align: center;">
            <a href="{{ url_for('list_files') }}" style="color: #667eea; text-decoration: none;">
                📋 View uploaded files
            </a>
        </div>
    </div>
    
    <script>
        const uploadArea = document.getElementById('upload-area');
        const fileInput = document.getElementById('file-input');
        const fileList = document.getElementById('file-list');
        const uploadForm = document.getElementById('upload-form');
        const progressBar = document.getElementById('progress-bar');
        const progress = document.getElementById('progress');
        
        // Click to open file dialog
        uploadArea.addEventListener('click', () => fileInput.click());
        
        // Drag and drop handlers
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.classList.add('dragover');
            });
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => {
                uploadArea.classList.remove('dragover');
            });
        });
        
        uploadArea.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            fileInput.files = files;
            updateFileList(files);
        });
        
        // File selection
        fileInput.addEventListener('change', (e) => {
            updateFileList(e.target.files);
        });
        
        function updateFileList(files) {
            fileList.innerHTML = '';
            for (let file of files) {
                const fileItem = document.createElement('div');
                fileItem.className = 'file-item';
                fileItem.innerHTML = `
                    <span>📄</span>
                    <span class="file-name">${file.name}</span>
                    <span class="file-size">${formatFileSize(file.size)}</span>
                `;
                fileList.appendChild(fileItem);
            }
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }
        
        // Upload progress (simulated for small files)
        uploadForm.addEventListener('submit', (e) => {
            const uploadBtn = document.getElementById('upload-btn');
            uploadBtn.disabled = true;
            uploadBtn.textContent = 'Uploading...';
            progressBar.style.display = 'block';
            
            let width = 0;
            const interval = setInterval(() => {
                if (width >= 90) {
                    clearInterval(interval);
                } else {
                    width += Math.random() * 20;
                    progress.style.width = Math.min(width, 90) + '%';
                }
            }, 200);
            
            // Real upload handling is done by the browser
            setTimeout(() => {
                progress.style.width = '100%';
            }, 1000);
        });
    </script>
</body>
</html>
'''

FILES_LIST_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Uploaded Files</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 800px;
            margin: 0 auto;
        }
        
        h1 {
            color: #333;
            margin-bottom: 30px;
        }
        
        .file-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .file-table th {
            background: #f5f5f5;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
        }
        
        .file-table td {
            padding: 12px;
            border-bottom: 1px solid #eee;
        }
        
        .file-table tr:hover {
            background: #f9f9f9;
        }
        
        .file-size {
            color: #666;
        }
        
        .file-date {
            color: #666;
            font-size: 0.9em;
        }
        
        .no-files {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 25px;
            margin-top: 20px;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .delete-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            font-size: 0.9em;
        }
        
        .delete-btn:hover {
            background: #c82333;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 Uploaded Files</h1>
        
        {% if files %}
            <table class="file-table">
                <thead>
                    <tr>
                        <th>Filename</th>
                        <th>Size</th>
                        <th>Category</th>
                        <th>Uploaded</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for file in files %}
                    <tr>
                        <td>
                            <a href="{{ url_for('download_file', filename=file.path) }}">
                                {{ file.name }}
                            </a>
                        </td>
                        <td class="file-size">{{ file.size }}</td>
                        <td>{{ file.category }}</td>
                        <td class="file-date">{{ file.date }}</td>
                        <td>
                            <a href="{{ url_for('delete_file', filename=file.path) }}" 
                               class="delete-btn"
                               onclick="return confirm('Are you sure you want to delete this file?')">
                                Delete
                            </a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="no-files">
                <p>📭 No files uploaded yet</p>
            </div>
        {% endif %}
        
        <a href="{{ url_for('upload_form') }}" class="btn">← Back to Upload</a>
    </div>
</body>
</html>
'''


@app.route('/')
@app.route('/upload')
def upload_form():
    """Render the upload form."""
    return render_template_string(UPLOAD_FORM_TEMPLATE)


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload."""
    # Check if file is present in request
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('upload_form'))
    
    file = request.files['file']
    
    # Check if filename is empty
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('upload_form'))
    
    # Validate file extension
    if not allowed_file(file.filename):
        flash(f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
        return redirect(url_for('upload_form'))
    
    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > MAX_FILE_SIZE:
        flash(f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB', 'error')
        return redirect(url_for('upload_form'))
    
    # Validate MIME type (optional but recommended)
    # Uncomment if you have python-magic installed
    # if not validate_file_mime_type(file):
    #     flash('Invalid file type detected', 'error')
    #     return redirect(url_for('upload_form'))
    
    try:
        # Generate safe filename
        safe_filename = generate_safe_filename(file.filename)
        
        # Determine category subdirectory
        category = get_file_category(file.filename)
        upload_path = UPLOAD_FOLDER / category
        
        # Save the file
        file_path = upload_path / safe_filename
        file.save(str(file_path))
        
        # Calculate file hash for integrity
        file_hash = calculate_file_hash(file_path)
        
        # Log upload
        app.logger.info(f"File uploaded: {safe_filename} ({file_size} bytes, hash: {file_hash})")
        
        flash(f'File "{file.filename}" uploaded successfully!', 'success')
        
    except Exception as e:
        app.logger.error(f"Upload failed: {str(e)}")
        flash(f'Upload failed: {str(e)}', 'error')
    
    return redirect(url_for('upload_form'))


@app.route('/files')
def list_files():
    """List all uploaded files."""
    files = []
    
    try:
        for category_dir in UPLOAD_FOLDER.iterdir():
            if category_dir.is_dir():
                for file_path in category_dir.iterdir():
                    if file_path.is_file():
                        stat = file_path.stat()
                        files.append({
                            'name': file_path.name,
                            'path': str(file_path.relative_to(UPLOAD_FOLDER)),
                            'size': format_file_size(stat.st_size),
                            'category': category_dir.name,
                            'date': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        })
        
        # Sort by date, newest first
        files.sort(key=lambda x: x['date'], reverse=True)
        
    except Exception as e:
        flash(f'Error reading files: {str(e)}', 'error')
    
    return render_template_string(FILES_LIST_TEMPLATE, files=files)


@app.route('/uploads/<path:filename>')
def download_file(filename):
    """Download or view an uploaded file."""
    try:
        return send_from_directory(
            str(UPLOAD_FOLDER), 
            filename, 
            as_attachment=False
        )
    except FileNotFoundError:
        flash('File not found', 'error')
        return redirect(url_for('list_files'))


@app.route('/delete/<path:filename>')
def delete_file(filename):
    """Delete an uploaded file."""
    try:
        file_path = UPLOAD_FOLDER / filename
        
        # Security check - ensure file is within upload directory
        if not str(file_path.resolve()).startswith(str(UPLOAD_FOLDER.resolve())):
            flash('Invalid file path', 'error')
            return redirect(url_for('list_files'))
        
        if file_path.exists():
            file_path.unlink()
            app.logger.info(f"File deleted: {filename}")
            flash(f'File deleted successfully', 'success')
        else:
            flash('File not found', 'error')
            
    except Exception as e:
        app.logger.error(f"Delete failed: {str(e)}")
        flash(f'Error deleting file: {str(e)}', 'error')
    
    return redirect(url_for('list_files'))


# API Endpoints for programmatic access

@app.route('/api/upload', methods=['POST'])
def api_upload():
    """API endpoint for file upload."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({
            'error': 'File type not allowed',
            'allowed_types': list(ALLOWED_EXTENSIONS)
        }), 400
    
    try:
        safe_filename = generate_safe_filename(file.filename)
        category = get_file_category(file.filename)
        upload_path = UPLOAD_FOLDER / category
        file_path = upload_path / safe_filename
        file.save(str(file_path))
        
        file_hash = calculate_file_hash(file_path)
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'file': {
                'original_name': file.filename,
                'saved_name': safe_filename,
                'path': str(file_path.relative_to(UPLOAD_FOLDER)),
                'category': category,
                'size': file_path.stat().st_size,
                'hash': file_hash
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/files', methods=['GET'])
def api_list_files():
    """API endpoint to list all files."""
    files = []
    
    for category_dir in UPLOAD_FOLDER.iterdir():
        if category_dir.is_dir():
            for file_path in category_dir.iterdir():
                if file_path.is_file():
                    stat = file_path.stat()
                    files.append({
                        'name': file_path.name,
                        'relative_path': str(file_path.relative_to(UPLOAD_FOLDER)),
                        'size': stat.st_size,
                        'category': category_dir.name,
                        'uploaded': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
    
    return jsonify({
        'success': True,
        'total_files': len(files),
        'files': sorted(files, key=lambda x: x['uploaded'], reverse=True)
    }), 200


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


# Error handlers
@app.errorhandler(413)
def too_large(e):
    """Handle file too large error."""
    if request.path.startswith('/api'):
        return jsonify({'error': 'File is too large'}), 413
    flash('File is too large. Maximum size is 16 MB', 'error')
    return redirect(url_for('upload_form'))


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Install required packages:
    # pip install flask python-magic
    
    print("=" * 60)
    print("📁 Flask File Upload Server")
    print("=" * 60)
    print(f"Upload folder: {UPLOAD_FOLDER.absolute()}")
    print(f"Max file size: {MAX_FILE_SIZE // (1024*1024)} MB")
    print(f"Allowed types: {', '.join(ALLOWED_EXTENSIONS)}")
    print("=" * 60)
    print("\nServer starting at http://localhost:5000")
    print("Upload form: http://localhost:5000/upload")
    print("File list: http://localhost:5000/files")
    print("API: http://localhost:5000/api/upload")
    print("-" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)