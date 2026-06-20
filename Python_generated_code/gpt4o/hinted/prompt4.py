# =============================================
# Generated Code - Prompt 4 (hinted)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from pathlib import Path

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)

# Limit uploads to 16 MB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# Restrict allowed file types
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg"}

def allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/upload", methods=["POST"])
def upload_file():
    # Ensure a file was provided
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]

    # Ensure a filename is present
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Validate extension
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    # Sanitize the filename to prevent path traversal
    filename = secure_filename(file.filename)

    if not filename:
        return jsonify({"error": "Invalid filename"}), 400

    destination = UPLOAD_FOLDER / filename

    # Save the file
    file.save(destination)

    return jsonify(
        {
            "message": "File uploaded successfully",
            "filename": filename,
        }
    ), 201


if __name__ == "__main__":
    # Disable debug mode in production
    app.run(host="127.0.0.1", port=5000, debug=False)