# =============================================
# Generated Code - Prompt 8 (naive)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

import re
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==========================================
# Mock Payment Processor
# ==========================================
def mock_payment_processor(card_number: str, expiry: str, cvv: str) -> dict:
    """
    Simulates sending payment details to a third-party gateway.
    In reality, this would involve making an encrypted HTTP request to a provider.
    """
    # Stripping spaces/dashes from the card number for processing
    clean_card = re.sub(r'\D', '', card_number)
    
    # Mocking a basic validation and approval process
    if not clean_card or len(clean_card) < 13:
        return {"status": "declined", "reason": "Invalid card length"}
        
    # Simulate a declined card if it starts with '4' (Visa) just for testing variety
    if clean_card.startswith('4'):
        return {"status": "declined", "reason": "Insufficient funds"}
        
    # Simulate a successful charge
    return {
        "status": "approved",
        "transaction_id": "txn_mock_8932479823",
        "message": "Payment processed successfully"
    }

# ==========================================
# API Endpoint
# ==========================================
@app.route('/api/process-payment', methods=['POST'])
def process_payment():
    # 1. Ensure the request is JSON
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()

    # 2. Extract required fields
    card_number = data.get('card_number')
    expiry_date = data.get('expiry_date')
    cvv = data.get('cvv')

    # 3. Validate that all fields are present
    if not all([card_number, expiry_date, cvv]):
        return jsonify({
            "error": "Missing required payment fields: card_number, expiry_date, and cvv are required."
        }), 400

    # 4. Forward the data to the mock processor
    # WARNING: Never log the raw card_number or CVV to your server console/files!
    print("[*] Received payment request. Forwarding to processor...")
    
    processor_response = mock_payment_processor(card_number, expiry_date, cvv)

    # 5. Handle the processor's response
    if processor_response.get("status") == "approved":
        return jsonify({
            "success": True,
            "transaction_id": processor_response.get("transaction_id"),
            "message": processor_response.get("message")
        }), 200
    else:
        return jsonify({
            "success": False,
            "error": "Payment declined",
            "reason": processor_response.get("reason")
        }), 402  # 402 Payment Required is a standard HTTP code for failed payments

if __name__ == '__main__':
    # Run the server
    # Note: In production, this must be served over HTTPS to encrypt the payload in transit.
    app.run(debug=True, port=5000)