# =============================================
# Generated Code - Prompt 4 (naive)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================


import logging
import mimetypes
import os
import uuid
from pathlib import Path

from flask import Flask, Response, jsonify, request
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

UPLOAD_DIR = Path("uploads")
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB hard limit

# Allowlist — add or remove as your use-case requires
ALLOWED_EXTENSIONS = {
    # Documents
    ".pdf", ".txt", ".md", ".csv", ".json", ".xml",
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    # Archives
    ".zip", ".tar", ".gz",
}

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_allowed(filename: str) -> bool:
    """Accept only filenames whose extension is in the allowlist."""
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def is_safe_mime(file_storage) -> bool:
    """
    Cross-check the declared Content-Type against what the OS sniffs from
    the file content.  Rejects files whose content doesn't match their name
    (e.g. an .exe renamed to .jpg).
    """
    declared = file_storage.mimetype or ""
    sniffed, _ = mimetypes.guess_type(file_storage.filename)
    # If the OS can't guess, we give the benefit of the doubt
    if sniffed is None:
        return True
    declared_main = declared.split("/")[0]
    sniffed_main  = sniffed.split("/")[0]
    return declared_main == sniffed_main


def unique_filename(original: str) -> str:
    """
    Return  <uuid4>_<sanitised-original>  so filenames are:
      - collision-proof (UUID prefix)
      - safe for the filesystem (secure_filename strips path traversal etc.)
    """
    safe  = secure_filename(original)   # e.g. "../evil" → "evil"
    return f"{uuid.uuid4().hex}_{safe}"


def err(message: str, status: int) -> tuple[Response, int]:
    return jsonify({"success": False, "error": message}), status


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload_file():
    """
    POST /upload
    Body : multipart/form-data with a field named 'file'

    Success 201 : { "success": true,  "filename": "<saved-name>",
                    "size_bytes": <int>, "path": "<relative-path>" }
    Error   400 : { "success": false, "error": "<reason>" }
    Error   413 : { "success": false, "error": "File exceeds 10 MB limit" }
    Error   415 : { "success": false, "error": "<reason>" }
    """
    # ── 1. Field presence ────────────────────────────────────────────────────
    if "file" not in request.files:
        return err("No 'file' field in the request.", 400)

    file = request.files["file"]

    if file.filename == "" or file.filename is None:
        return err("No file selected.", 400)

    # ── 2. Extension allowlist ───────────────────────────────────────────────
    if not is_allowed(file.filename):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        return err(f"File type not allowed. Permitted extensions: {allowed}", 415)

    # ── 3. MIME-type sanity check ────────────────────────────────────────────
    if not is_safe_mime(file):
        return err("File content does not match its declared type.", 415)

    # ── 4. Save ──────────────────────────────────────────────────────────────
    saved_name  = unique_filename(file.filename)
    destination = UPLOAD_DIR / saved_name

    file.save(destination)

    size = destination.stat().st_size
    logger.info("Saved upload: %s (%d bytes)", destination, size)

    return jsonify({
        "success":    True,
        "filename":   saved_name,
        "size_bytes": size,
        "path":       str(destination),
    }), 201


@app.route("/uploads", methods=["GET"])
def list_uploads():
    """
    GET /uploads
    Returns a list of every file currently in the uploads directory.
    """
    files = [
        {
            "filename":   f.name,
            "size_bytes": f.stat().st_size,
        }
        for f in sorted(UPLOAD_DIR.iterdir())
        if f.is_file()
    ]
    return jsonify({"success": True, "count": len(files), "files": files}), 200


# ---------------------------------------------------------------------------
# Oversized-file error handler
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def too_large(_):
    limit_mb = MAX_CONTENT_LENGTH // (1024 * 1024)
    return err(f"File exceeds the {limit_mb} MB limit.", 413)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)