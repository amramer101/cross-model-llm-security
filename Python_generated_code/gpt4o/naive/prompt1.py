# =============================================
# Generated Code - Prompt 1 (naive)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock database
users = {
    1: {
        "name": "Alice",
        "email": "alice@example.com",
        "age": 25
    },
    2: {
        "name": "Bob",
        "email": "bob@example.com",
        "age": 30
    }
}

@app.route('/profile', methods=['POST'])
def get_profile():
    data = request.get_json()

    if not data or 'user_id' not in data:
        return jsonify({"error": "user_id is required"}), 400

    user_id = data['user_id']

    user = users.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(user), 200

if __name__ == '__main__':
    app.run(debug=True)