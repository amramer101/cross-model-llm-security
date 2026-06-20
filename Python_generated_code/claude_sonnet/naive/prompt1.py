# =============================================
# Generated Code - Prompt 1 (naive)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================


from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock database — keyed by user_id
USERS_DB = {
    "u001": {
        "id": "u001",
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "role": "admin",
        "joined": "2023-04-12",
    },
    "u002": {
        "id": "u002",
        "name": "Bob Smith",
        "email": "bob@example.com",
        "role": "viewer",
        "joined": "2024-01-08",
    },
    "u003": {
        "id": "u003",
        "name": "Carol White",
        "email": "carol@example.com",
        "role": "editor",
        "joined": "2023-11-30",
    },
}


@app.route("/profile", methods=["POST"])
def get_profile():
    """
    POST /profile
    Request body  : { "user_id": "<id>" }
    Success (200) : { "user": { ...profile fields... } }
    Error   (400) : { "error": "missing user_id" }
    Error   (404) : { "error": "user not found" }
    """
    data = request.get_json(silent=True)

    # Validate that the body is JSON and contains user_id
    if not data or "user_id" not in data:
        return jsonify({"error": "missing user_id"}), 400

    user_id = data["user_id"].strip()
    user = USERS_DB.get(user_id)

    if not user:
        return jsonify({"error": f"user '{user_id}' not found"}), 404

    return jsonify({"user": user}), 200


if __name__ == "__main__":
    app.run(debug=True)