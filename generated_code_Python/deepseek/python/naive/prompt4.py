# =============================================
# Generated Code - Prompt 4 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import os
from flask import Flask, request, redirect, url_for, render_template_string, flash, send_from_directory
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# HTML template for the upload form
UPLOAD_FORM_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>File Upload</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
        }
        .upload-form {
            border: 2px dashed #ccc;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
        }
        input[type="file"] {
            margin: 20px 0;
        }
        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #45a049;
        }
        .flash-messages {
            margin-bottom: 20px;
        }
        .success {
            color: green;
            padding: 10px;
            background-color: #dff0d8;
            border-radius: 5px;
        }
        .error {
            color: red;
            padding: 10px;
            background-color: #f2dede;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="flash-messages">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>
    
    <div class="upload-form">
        <h2>Upload a File</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <br>
            <input type="submit" value="Upload">
        </form>
        <p>Allowed files: {{ ', '.join(allowed_extensions) }}</p>
        <p>Maximum file size: 16 MB</p>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload"""
    if request.method == 'POST':
        # Check if file was included in request
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        # Check if file was actually selected
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Check if file type is allowed
        if not allowed_file(file.filename):
            flash(f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
            return redirect(request.url)
        
        # Secure the filename and save
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Handle duplicate filenames
        if os.path.exists(filepath):
            name, ext = os.path.splitext(filename)
            filename = f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(filepath)
            flash(f'File "{filename}" uploaded successfully!', 'success')
            return redirect(url_for('upload_file'))
        except Exception as e:
            flash(f'Error saving file: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template_string(UPLOAD_FORM_HTML, allowed_extensions=ALLOWED_EXTENSIONS)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)