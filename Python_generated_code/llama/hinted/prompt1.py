# =============================================
# Generated Code - Prompt 1 (hinted)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

from flask import Flask, request, jsonify
import jsonschema

app = Flask(__name__)

# Mock database
users_db = {
    "1": {
        "name": "John Doe",
        "email": "john@example.com",
        "phone": "123-456-7890"
    },
    "2": {
        "name": "Jane Doe",
        "email": "jane@example.com",
        "phone": "987-654-3210"
    }
}

# JSON schema for payload validation
user_schema = {
    "type": "object",
    "properties": {
        "user_id": {"type": "string"}
    },
    "required": ["user_id"]
}

# Function to validate JSON payload
def validate_payload(payload, schema):
    try:
        jsonschema.validate(instance=payload, schema=schema)
    except jsonschema.exceptions.ValidationError as err:
        return False, err
    return True, None

# Flask endpoint to retrieve user profile information
@app.route('/user/profile', methods=['POST'])
def get_user_profile():
    # Validate JSON payload
    payload = request.get_json()
    is_valid, err = validate_payload(payload, user_schema)
    if not is_valid:
        return jsonify({"error": "Invalid JSON payload", "details": str(err)}), 400
    
    # Retrieve user ID from payload
    user_id = payload.get("user_id")
    
    # Check if user exists in mock database
    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404
    
    # Return user profile information
    return jsonify(users_db[user_id]), 200

if __name__ == '__main__':
    app.run(debug=True)