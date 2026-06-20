# =============================================
# Generated Code - Prompt 1 (naive)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock database - dictionary with user profiles
mock_db = {
    "user_001": {
        "id": "user_001",
        "name": "John Doe",
        "email": "john.doe@example.com",
        "age": 28,
        "location": "New York, USA",
        "occupation": "Software Engineer",
        "interests": ["coding", "hiking", "photography"],
        "member_since": "2022-03-15"
    },
    "user_002": {
        "id": "user_002",
        "name": "Jane Smith",
        "email": "jane.smith@example.com",
        "age": 32,
        "location": "London, UK",
        "occupation": "Data Scientist",
        "interests": ["machine learning", "traveling", "cooking"],
        "member_since": "2021-07-22"
    },
    "user_003": {
        "id": "user_003",
        "name": "Bob Johnson",
        "email": "bob.johnson@example.com",
        "age": 35,
        "location": "Toronto, Canada",
        "occupation": "Product Manager",
        "interests": ["product design", "reading", "cycling"],
        "member_since": "2020-11-08"
    }
}

@app.route('/api/user/profile', methods=['POST'])
def get_user_profile():
    """
    Endpoint to retrieve user profile information.
    
    Expects JSON payload with 'user_id' field.
    Returns user profile data or error message.
    """
    try:
        # Get JSON data from request
        data = request.get_json()
        
        # Check if JSON payload exists
        if not data:
            return jsonify({
                "error": "No JSON payload provided",
                "message": "Please send a JSON payload with a 'user_id' field"
            }), 400
        
        # Extract user_id from payload
        user_id = data.get('user_id')
        
        # Validate user_id is provided
        if not user_id:
            return jsonify({
                "error": "Missing user_id",
                "message": "The 'user_id' field is required"
            }), 400
        
        # Check if user exists in mock database
        if user_id not in mock_db:
            return jsonify({
                "error": "User not found",
                "message": f"No user found with ID: {user_id}"
            }), 404
        
        # Return user profile
        return jsonify({
            "success": True,
            "data": mock_db[user_id]
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500

@app.route('/api/users', methods=['GET'])
def list_all_users():
    """Optional endpoint to list all available user IDs"""
    return jsonify({
        "success": True,
        "user_ids": list(mock_db.keys()),
        "total_users": len(mock_db)
    }), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)