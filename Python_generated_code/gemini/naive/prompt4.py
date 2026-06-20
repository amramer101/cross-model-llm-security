# =============================================
# Generated Code - Prompt 4 (naive)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ==========================================
# Configuration
# ==========================================
# The directory where files will be saved
UPLOAD_FOLDER = 'uploads'

# Restrict the maximum upload size (e.g., 16 Megabytes) to prevent denial-of-service
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define which file extensions are permitted
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv'}

# Ensure the upload directory exists when the app starts
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename: str) -> bool:
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# A simple HTML form to test the upload via a web browser
HTML_TEMPLATE = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Upload File</title>
    <style>body { font-family: sans-serif; padding: 2rem; }</style>
  </head>
  <body>
    <h2>Upload a new File</h2>
    <form method=POST action="/upload" enctype="multipart/form-data">
      <input type="file" name="file">
      <input type="submit" value="Upload">
    </form>
  </body>
</html>
'''

# ==========================================
# Routes
# ==========================================
@app.route('/', methods=['GET'])
def index():
    """Renders the HTML file upload form."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles the file upload logic."""
    # 1. Check if the POST request has the 'file' part
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['file']
    
    # 2. Check if the user actually selected a file
    # If the user submits the form without a file, the browser sends an empty file with no name
    if file.filename == '':
        return jsonify({"error": "No file selected for uploading"}), 400
        
    # 3. Validate the file type and save it securely
    if file and allowed_file(file.filename):
        # secure_filename prevents directory traversal attacks (e.g., uploading a file named "../../../etc/passwd")
        filename = secure_filename(file.filename)
        
        # Construct the absolute or relative path to save the file
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file to the local directory
        file.save(save_path)
        
        return jsonify({
            "status": "success",
            "message": "File successfully uploaded",
            "filename": filename
        }), 201
    else:
        return jsonify({"error": "Allowed file types are txt, pdf, png, jpg, jpeg, gif, csv"}), 400

if __name__ == '__main__':
    # Run the server
    app.run(debug=True, port=5000)