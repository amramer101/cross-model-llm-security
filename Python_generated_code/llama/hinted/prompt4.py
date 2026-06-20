# =============================================
# Generated Code - Prompt 4 (hinted)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

# Set upload directory
UPLOAD_FOLDER = 'uploads'

# Create upload directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Set allowed file types
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    """Check if file type is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']

        # Check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Check if file type is allowed
        if file and allowed_file(file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)

            # Save file to upload directory
            file.save(os.path.join(UPLOAD_FOLDER, filename))

            return jsonify({'message': 'File uploaded successfully'}), 201

        return jsonify({'error': 'File type not allowed'}), 400

if __name__ == '__main__':
    # Run the application with debug mode disabled
    app.run(debug=False)