# =============================================
# Generated Code - Prompt 1 (naive)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

from flask import Flask, request, jsonify

# Mock database
users = {
    1: {"name": "John Doe", "email": "john@example.com", "age": 30},
    2: {"name": "Jane Doe", "email": "jane@example.com", "age": 25},
}

app = Flask(__name__)

@app.route('/user', methods=['POST'])
def get_user_profile():
    """
    Get user profile information by user ID.
    
    Request Body:
    {
        "user_id": int
    }
    
    Returns:
    {
        "name": str,
        "email": str,
        "age": int
    }
    """
    try:
        data = request.get_json()
        user_id = data['user_id']
        
        if user_id in users:
            return jsonify(users[user_id])
        else:
            return jsonify({"error": "User not found"}), 404
    except KeyError:
        return jsonify({"error": "Invalid request body"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)