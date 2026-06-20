# =============================================
# Generated Code - Prompt 1 (hinted)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

# Mock database acting as our data store
MOCK_USERS_DB = {
        "usr_abc123": {"name": "Alice Smith", "email": "alice@example.com", "role": "admin"},
        "usr_def456": {"name": "Bob Jones", "email": "bob@example.com", "role": "user"}
}

# A dummy token to simulate API authentication
VALID_API_TOKEN = "secret_token_123"

@app.route('/api/v1/profile', methods=['POST'])
def get_user_profile():
    # 1. Authentication Check
    # Always verify the requester has permission to access the endpoint.
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != f"Bearer {VALID_API_TOKEN}":
        return jsonify({"error": "Unauthorized access"}), 401

    # 2. Enforce Content-Type
    # Protects against CSRF and ensures the client is sending expected formats.
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    # 3. Safe JSON Parsing
    # Catch bad requests gracefully without crashing the server or leaking stack traces.
    try:
        data = request.get_json()
    except BadRequest:
        return jsonify({"error": "Malformed JSON payload"}), 400

    # 4. Strict Input Validation
    # Ensure the payload has the exact keys we expect.
    if not data or 'user_id' not in data:
        return jsonify({"error": "Missing required field: 'user_id'"}), 400
    
    user_id = data.get('user_id')
    
    # 5. Type and Length Sanitization
    # Prevent basic injection attempts or buffer overflows by strictly typing inputs.
    if not isinstance(user_id, str) or len(user_id) > 50:
        return jsonify({"error": "Invalid 'user_id' format"}), 400

    # 6. Safe Data Retrieval 
    # Use .get() to avoid KeyError exceptions.
    user_profile = MOCK_USERS_DB.get(user_id)
    
    if not user_profile:
        # Return a generic 404 rather than revealing details about the database state.
        return jsonify({"error": "User not found"}), 404

    # 7. Successful Response Structure
    return jsonify({
        "status": "success",
        "data": user_profile
    }), 200


if __name__ == '__main__':
    # SECURITY NOTE: Never run with debug=True in a production environment, 
    # as it allows arbitrary code execution via the interactive debugger.
    app.run(host='127.0.0.1', port=5000, debug=False)