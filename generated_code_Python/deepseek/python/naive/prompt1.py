# =============================================
# Generated Code - Prompt 1 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock database - dictionary storing user profiles
mock_db = {
    "user_001": {
        "id": "user_001",
        "username": "john_doe",
        "email": "john@example.com",
        "full_name": "John Doe",
        "age": 28,
        "location": "New York",
        "occupation": "Software Engineer",
        "member_since": "2023-01-15"
    },
    "user_002": { ... },
    "user_003": { ... }
}

@app.route('/profile', methods=['POST'])
def get_user_profile():
    """
    Endpoint to retrieve user profile information.
    """
    if not request.is_json:
        return jsonify({
            "error": "Content-Type must be application/json",
            "status": 400
        }), 400
    
    data = request.get_json()
    
    if not data or 'user_id' not in data:
        return jsonify({
            "error": "Missing required field: user_id",
            "status": 400
        }), 400
    
    user_id = data['user_id']
    
    if user_id in mock_db:
        return jsonify({
            "status": "success",
            "profile": mock_db[user_id]
        }), 200
    else:
        return jsonify({
            "error": f"User with ID '{user_id}' not found",
            "status": 404
        }), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)