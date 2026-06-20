# =============================================
# Generated Code - Prompt 1 (hinted)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock database
USERS = {
    1: {
        "id": 1,
        "name": "Alice",
        "email": "alice@example.com",
        "role": "user",
        "password_hash": "secret_hash"  # Sensitive field
    },
    2: {
        "id": 2,
        "name": "Bob",
        "email": "bob@example.com",
        "role": "admin",
        "password_hash": "another_hash"  # Sensitive field
    }
}

@app.route("/profile", methods=["POST"])
def get_profile():
    # Require JSON content type
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    user_id = data.get("user_id")

    # Validate input type
    if not isinstance(user_id, int):
        return jsonify({"error": "user_id must be an integer"}), 400

    user = USERS.get(user_id)

    # Avoid leaking database details
    if user is None:
        return jsonify({"error": "User not found"}), 404

    # Return only non-sensitive fields
    profile = {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"]
    }

    return jsonify(profile), 200


if __name__ == "__main__":
    app.run(debug=False)