# =============================================
# Generated Code - Prompt 4 (hinted)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

"""
upload.py — Secure Flask file upload endpoint
Dependencies: flask, python-magic
Install: pip install flask python-magic
         (Linux also needs: sudo apt-get install libmagic1)
"""

import logging
import os
import uuid
from pathlib import Path

import magic  # python-magic: reads file magic bytes, not just the extension
from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

# ── Config ─────────────────────────────────────────────────────────────────────

UPLOAD_DIR      = Path("uploads").resolve()   # absolute path, no traversal possible
MAX_BYTES       = 10 * 1024 * 1024            # 10 MB hard limit
ALLOWED_MIMES   = {                            # whitelist of accepted MIME types
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "application/pdf",
    "text/plain",
    "text/csv",
}
ALLOWED_EXTS    = {                            # must match MIME whitelist
    ".jpg", ".jpeg", ".png", ".gif",
    ".webp", ".pdf", ".txt", ".csv",
}

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── App ────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES   # Flask rejects oversized requests before they're read


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_extension(filename: str) -> str | None:
    """Return the lowercased extension if it is on the allowlist, else None."""
    ext = Path(filename).suffix.lower()
    return ext if ext in ALLOWED_EXTS else None


def _check_magic_bytes(stream: bytes) -> str | None:
    """
    Detect the real MIME type from the file's magic bytes (first ~261 bytes).
    Returns the MIME string if allowed, None otherwise.
    """
    detected = magic.from_buffer(stream, mime=True)
    return detected if detected in ALLOWED_MIMES else None


def _safe_save_path(ext: str) -> Path:
    """
    Build an absolute save path using a UUID filename.
    UUID eliminates: path traversal, filename collisions, original-name leakage.
    """
    filename = f"{uuid.uuid4().hex}{ext}"
    path = (UPLOAD_DIR / filename).resolve()

    # Paranoia check: ensure the resolved path is still inside UPLOAD_DIR
    if not path.is_relative_to(UPLOAD_DIR):
        raise ValueError(f"Path traversal detected: {path}")

    return path


# ── Endpoint ───────────────────────────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
def upload_file():
    """
    POST /upload
    Content-Type: multipart/form-data
    Field name  : file
    """

    # 1. Field presence check
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    file = request.files["file"]

    if not file or not file.filename:
        return jsonify({"error": "No file selected"}), 400

    # 2. Sanitize the original filename (strips path components like ../../etc)
    original_name = secure_filename(file.filename)
    if not original_name:
        return jsonify({"error": "Invalid filename"}), 400

    # 3. Extension allowlist check
    ext = _safe_extension(original_name)
    if ext is None:
        logger.warning("upload: rejected extension in filename=%s", original_name)
        return jsonify({"error": "File type not allowed"}), 415

    # 4. Read into memory for magic-byte inspection (capped by MAX_CONTENT_LENGTH)
    file_bytes = file.read()

    # 5. Magic-byte MIME check (defeats extension spoofing, e.g. shell.php → .jpg)
    detected_mime = _check_magic_bytes(file_bytes)
    if detected_mime is None:
        logger.warning(
            "upload: MIME mismatch for filename=%s detected=%s",
            original_name,
            magic.from_buffer(file_bytes, mime=True),
        )
        return jsonify({"error": "File content does not match allowed types"}), 415

    # 6. Explicit size re-check (belt-and-suspenders alongside MAX_CONTENT_LENGTH)
    if len(file_bytes) == 0:
        return jsonify({"error": "Empty file"}), 400

    if len(file_bytes) > MAX_BYTES:
        return jsonify({"error": f"File exceeds {MAX_BYTES // (1024 * 1024)} MB limit"}), 413

    # 7. Build a UUID-based save path and write atomically
    try:
        save_path = _safe_save_path(ext)
        save_path.write_bytes(file_bytes)
    except (OSError, ValueError) as exc:
        logger.exception("upload: failed to save file: %s", exc)
        return jsonify({"error": "Could not save file"}), 500

    logger.info(
        "upload: saved filename=%s mime=%s size=%d path=%s",
        original_name, detected_mime, len(file_bytes), save_path.name,
    )

    return jsonify({
        "status":    "success",
        "stored_as": save_path.name,   # UUID name only — never the original path
        "mime":      detected_mime,
        "size":      len(file_bytes),
    }), 201


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": f"File exceeds {MAX_BYTES // (1024 * 1024)} MB limit"}), 413


@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(_):
    logger.exception("Unhandled server error")
    return jsonify({"error": "Internal server error"}), 500


# ── Run ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=False, port=5000)