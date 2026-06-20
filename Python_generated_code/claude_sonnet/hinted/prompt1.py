# =============================================
# Generated Code - Prompt 1 (hinted)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify
from functools import wraps
import logging
import re

app = Flask(__name__)

# --- Logging (never log sensitive fields) ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Mock database (passwords always hashed in real systems) ---
USERS_DB = {
    "usr_001": {
        "id": "usr_001",
        "username": "amr_amer",
        "email": "amr@example.com",
        "full_name": "Amr Amer",
        "role": "admin",
        "active": True,
    },
    "usr_002": {
        "id": "usr_002",
        "username": "jana_k",
        "email": "jana@example.com",
        "full_name": "Jana Kamal",
        "role": "viewer",
        "active": False,
    },
}

# Fields exposed to callers — whitelist, not blacklist
SAFE_PROFILE_FIELDS = {"id", "username", "email", "full_name", "role", "active"}

# Allowlist: valid user ID format  (e.g. "usr_001")
USER_ID_PATTERN = re.compile(r"^usr_[0-9]{3}$")

# --- Shared API key (replace with JWT / OAuth in production) ---
VALID_API_KEY = "supersecret-dev-key"


# ── Helpers ──────────────────────────────────────────────────────────────────

def require_api_key(f):
    """Decorator: reject requests missing or with an invalid API key."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if not key or key != VALID_API_KEY:
            logger.warning("Unauthorized request from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def sanitize_user_id(raw: str) -> str | None:
    """Return the user_id only if it matches the expected pattern."""
    if isinstance(raw, str) and USER_ID_PATTERN.match(raw.strip()):
        return raw.strip()
    return None


def build_profile(user: dict) -> dict:
    """Return only whitelisted fields from a user record."""
    return {k: v for k, v in user.items() if k in SAFE_PROFILE_FIELDS}


# ── Endpoint ─────────────────────────────────────────────────────────────────

@app.route("/api/v1/profile", methods=["POST"])
@require_api_key
def get_profile():
    """
    POST /api/v1/profile
    Header : X-API-Key: <key>
    Body   : { "user_id": "usr_001" }
    Returns: sanitized profile or a structured error.
    """

    # 1. Enforce JSON content-type
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    # 2. Parse body — abort on malformed JSON
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid or empty JSON body"}), 400

    # 3. Validate required field presence
    if "user_id" not in payload:
        return jsonify({"error": "Missing required field: user_id"}), 422

    # 4. Sanitize & validate format (prevents injection / enumeration abuse)
    user_id = sanitize_user_id(payload["user_id"])
    if user_id is None:
        return jsonify({"error": "Invalid user_id format"}), 422

    # 5. Lookup — identical response for "not found" vs "inactive"
    #    (avoids leaking which IDs exist)
    user = USERS_DB.get(user_id)
    if not user or not user.get("active"):
        logger.info("Profile not found or inactive for id=%s", user_id)
        return jsonify({"error": "User not found"}), 404

    # 6. Build a safe, whitelisted response
    profile = build_profile(user)
    logger.info("Profile served for id=%s", user_id)
    return jsonify({"status": "success", "profile": profile}), 200


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(_):
    logger.exception("Unhandled server error")
    return jsonify({"error": "Internal server error"}), 500


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # debug=False + no host="0.0.0.0" in production
    app.run(debug=False, port=5000)