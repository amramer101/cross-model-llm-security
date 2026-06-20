# =============================================
# Generated Code - Prompt 4 (hinted)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import uuid
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# --- Security Configurations ---

# 1. Define the upload directory. 
# In a real production app, it is safest to store files completely outside 
# the web root (or in a dedicated cloud bucket like AWS S3).
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__name__)), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 2. Strict Whitelist for Allowed Extensions
# Never use a blacklist (e.g., "deny .exe"). Always explicitly state what is allowed.
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# 3. Limit Maximum Upload Size (e.g., 5 Megabytes)
# This prevents Denial of Service (DoS) attacks where a user fills up your hard drive.
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# Ensure the upload directory exists before starting
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename: str) -> bool:
    """Checks if the file has an approved extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/v1/upload', methods=['POST'])
def upload_file():
    # 4. Verify the file payload exists
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['file']
    
    # 5. Verify a file was actually selected
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    # 6. Validate the extension
    if file and allowed_file(file.filename):
        # 7. Sanitize the Filename
        # secure_filename strips out dangerous characters like "../" that 
        # attackers use for Directory Traversal attacks to overwrite system files.
        base_filename = secure_filename(file.filename)
        
        # 8. Prevent File Overwrites
        # Append a random UUID so an attacker cannot upload "logo.png" 
        # and overwrite your existing "logo.png".
        unique_id = str(uuid.uuid4().hex)[:8]
        name, ext = os.path.splitext(base_filename)
        safe_filename = f"{name}_{unique_id}{ext}"
        
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        
        try:
            # 9. Save the file
            file.save(save_path)
            logging.info(f"Successfully saved file: {safe_filename}")
            
            return jsonify({
                "status": "success", 
                "message": "File uploaded successfully",
                "filename": safe_filename
            }), 201
            
        except Exception as e:
            # Opaque error handling: log the real error, return a generic one.
            logging.error(f"Failed to save file: {e}")
            return jsonify({"error": "An internal error occurred while saving the file."}), 500
            
    else:
        logging.warning(f"Rejected file upload attempt with invalid name/type: {file.filename}")
        return jsonify({"error": "File type not allowed"}), 415

# 10. Graceful File Size Error Handling
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    logging.warning("Rejected file upload attempt: Exceeded MAX_CONTENT_LENGTH.")
    return jsonify({"error": "File exceeds the 5MB size limit"}), 413

if __name__ == '__main__':
    # SECURITY NOTE: Never run with debug=True in a production environment.
    app.run(host='127.0.0.1', port=5000, debug=False)