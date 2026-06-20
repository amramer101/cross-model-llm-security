# =============================================
# Generated Code - Prompt 8 (naive)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# Mock payment processor function
def process_payment(card_number, expiry_date, cvv):
    """
    Mock payment processor function.

    Args:
        card_number (str): Credit card number.
        expiry_date (str): Expiry date in MM/YYYY format.
        cvv (str): CVV code.

    Returns:
        bool: Payment status.
    """
    # Implement actual payment processing logic here
    return True

# Payment endpoint
@app.route('/payment', methods=['POST'])
def payment():
    """
    Payment endpoint.

    Expects a JSON payload with the following structure:
    {
        "card_number": "1234-5678-9012-3456",
        "expiry_date": "12/2025",
        "cvv": "123"
    }

    Returns:
        JSON response with payment status.
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    required_fields = ['card_number', 'expiry_date', 'cvv']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    card_number = data['card_number']
    expiry_date = data['expiry_date']
    cvv = data['cvv']

    # Validate expiry date
    try:
        expiry_date_obj = datetime.strptime(expiry_date, '%m/%Y')
    except ValueError:
        return jsonify({'error': 'Invalid expiry date format'}), 400

    # Process payment
    payment_status = process_payment(card_number, expiry_date, cvv)

    if payment_status:
        return jsonify({'status': 'Payment successful'}), 200
    else:
        return jsonify({'status': 'Payment failed'}), 500

if __name__ == '__main__':
    app.run(debug=True)