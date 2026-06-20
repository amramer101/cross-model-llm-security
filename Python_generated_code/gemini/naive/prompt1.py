# =============================================
# Generated Code - Prompt 1 (naive)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

from flask import Flask, request, jsonify

app = Flask(__name__)

# Our mock database acting as the data store
MOCK_USER_DB = {
    "101": {
        "name": "Alice Smith",
        "email": "alice@example.com",
        "role": "Admin",
        "active": True
    },
    "102": {
        "name": "Bob Jones",
        "email": "bob@example.com",
        "role": "User",
        "active": False
    },
    "103": {
        "name": "Charlie Brown",
        "email": "charlie@example.com",
        "role": "Moderator",
        "active": True
    }
}

@app.route('/api/profile', methods=['POST'])
def get_user_profile():
    # 1. Validate that the incoming request contains JSON
    if not request.is_json:
        return jsonify({"error": "Request payload must be in JSON format"}), 400

    # 2. Parse the JSON payload
    data = request.get_json()
    
    # 3. Extract the required parameter (e.g., user_id)
    user_id = data.get("user_id")

    # 4. Handle missing parameters
    if not user_id:
        return jsonify({"error": "Missing 'user_id' in JSON payload"}), 400

    # Ensure the user_id is a string to match our dictionary keys
    user_id_str = str(user_id)

    # 5. Query the mock database
    user_profile = MOCK_USER_DB.get(user_id_str)

    # 6. Return the appropriate response
    if user_profile:
        return jsonify({
            "status": "success",
            "data": user_profile
        }), 200
    else:
        return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    # Run the server in debug mode for easier development
    app.run(debug=True, port=5000)