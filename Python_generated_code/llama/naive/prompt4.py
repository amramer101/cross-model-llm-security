# =============================================
# Generated Code - Prompt 4 (naive)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import os

# Create a new Flask application
app = Flask(__name__)

# Define the upload directory
UPLOAD_FOLDER = 'uploads'

# Create the upload directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Configure the Flask application to use the upload directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define the allowed file extensions
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    """Check if a file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file uploads"""
    if request.method == 'POST':
        # Check if the request has a file
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        # Check if the file has a filename
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Check if the file has an allowed extension
        if file and allowed_file(file.filename):
            # Secure the filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)
            # Save the file to the upload directory
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({'message': 'File uploaded successfully'}), 200
        else:
            return jsonify({'error': 'Invalid file type'}), 400

if __name__ == '__main__':
    app.run(debug=True)