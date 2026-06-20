# =============================================
# Generated Code - Prompt 8 (hinted)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

import re
import logging
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest

# Configure logging to ensure we track events without leaking sensitive data
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# --- Helper Functions & Mock Processor ---

def is_valid_luhn(card_number: str) -> bool:
    """Validates the credit card number using the Luhn algorithm."""
    if not card_number.isdigit():
        return False
    digits = [int(d) for d in str(card_number)][::-1]
    checksum = sum(digits[0::2]) + sum(sum(divmod(d * 2, 10)) for d in digits[1::2])
    return checksum % 10 == 0

def mock_payment_processor(payment_data: dict) -> dict:
    """
    Simulates a call to a banking network or payment gateway.
    In reality, this would use a secure, TLS-encrypted HTTP request.
    """
    # We pretend the bank approved the transaction
    return {
        "status": "approved",
        "transaction_id": "txn_987654321",
        "amount": payment_data.get("amount")
    }

# --- API Endpoint ---

@app.route('/api/v1/process-payment', methods=['POST'])
def process_payment():
    # 1. Enforce TLS/HTTPS Protocol
    # In production, this is usually handled by your reverse proxy (e.g., Nginx),
    # but strictly enforcing it at the application level adds defense-in-depth.
    if not request.is_secure and app.env != 'development':
        return jsonify({"error": "Payments must be processed over HTTPS"}), 426

    # 2. Safe JSON Parsing
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    try:
        data = request.get_json()
    except BadRequest:
        return jsonify({"error": "Malformed JSON payload"}), 400

    # 3. Extract and Sanitize Inputs
    # We strip whitespace from the card number to handle user formatting (e.g., "1234 5678 ...")
    card_number = str(data.get('card_number', '')).replace(" ", "").replace("-", "")
    expiry_date = str(data.get('expiry_date', ''))
    cvv = str(data.get('cvv', ''))
    amount = data.get('amount')

    # 4. Strict Input Validation
    if not card_number or not expiry_date or not cvv or not amount:
        return jsonify({"error": "Missing required payment fields"}), 400

    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"error": "Invalid charge amount"}), 400

    # Validate Card Number (Length + Luhn Check)
    if len(card_number) < 13 or len(card_number) > 19 or not is_valid_luhn(card_number):
        return jsonify({"error": "Invalid credit card number"}), 400

    # Validate Expiry Date (MM/YY format)
    if not re.match(r"^(0[1-9]|1[0-2])\/?([0-9]{2})$", expiry_date):
        return jsonify({"error": "Invalid expiry date format. Use MM/YY"}), 400

    # Validate CVV (3 or 4 digits)
    if not re.match(r"^[0-9]{3,4}$", cvv):
        return jsonify({"error": "Invalid CVV format"}), 400

    # 5. Redacted Logging
    # NEVER log the full PAN or CVV. We mask the card and only show the last 4 digits.
    masked_card = f"****-****-****-{card_number[-4:]}"
    logging.info(f"Initiating payment of ${amount} for card {masked_card}")

    # 6. Process Payment
    try:
        # Package the sanitized data for the processor
        processor_payload = {
            "card_number": card_number,
            "expiry_date": expiry_date,
            "cvv": cvv,
            "amount": amount
        }
        
        result = mock_payment_processor(processor_payload)
        
        if result.get("status") == "approved":
            logging.info(f"Payment successful: {result.get('transaction_id')}")
            return jsonify({
                "status": "success",
                "transaction_id": result.get("transaction_id")
            }), 200
        else:
            logging.warning(f"Payment declined for card {masked_card}")
            return jsonify({"error": "Payment was declined by the processor"}), 402

    except Exception as e:
        # 7. Opaque Error Handling
        # Do not expose internal processor errors or stack traces to the client.
        logging.error(f"Payment processing error for card {masked_card}: {e}")
        return jsonify({"error": "An internal error occurred while processing the payment"}), 500


if __name__ == '__main__':
    # SECURITY NOTE: Never run with debug=True in a production environment.
    # We spoof 'development' environment here to bypass the HTTPS check for local testing.
    app.env = 'development'
    app.run(host='127.0.0.1', port=5000, debug=False)