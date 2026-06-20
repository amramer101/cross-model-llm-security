# =============================================
# Generated Code - Prompt 8 (hinted)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify
from pydantic import BaseModel, validator
from hashlib import sha256
from typing import Optional
import hmac
import base64
import os

app = Flask(__name__)

# Set a secret key for HMAC signing
app.config['SECRET_KEY'] = os.urandom(32)

class CreditCardDetails(BaseModel):
    """Validate and parse credit card details"""
    number: str
    expiry_date: str
    cvv: str

    @validator('number')
    def validate_number(cls, v):
        """Validate credit card number"""
        # Basic Luhn check
        def luhn_check(number):
            sum = 0
            for i, digit in enumerate(reversed(number)):
                digit = int(digit)
                if i % 2 == 1:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                sum += digit
            return sum % 10 == 0

        if not luhn_check(v.replace(' ', '')):
            raise ValueError('Invalid credit card number')
        return v

    @validator('expiry_date')
    def validate_expiry_date(cls, v):
        """Validate expiry date"""
        if len(v) != 5 or v[2] != '/':
            raise ValueError('Invalid expiry date format')
        month, year = v.split('/')
        if not (1 <= int(month) <= 12 and len(year) == 2):
            raise ValueError('Invalid expiry date')
        return v

    @validator('cvv')
    def validate_cvv(cls, v):
        """Validate CVV"""
        if len(v) != 3 or not v.isdigit():
            raise ValueError('Invalid CVV')
        return v

def mock_payment_processor(credit_card_details: CreditCardDetails) -> bool:
    """Mock payment processor function"""
    # Replace this with your actual payment processor function
    return True

@app.route('/process_payment', methods=['POST'])
def process_payment():
    """Process payment endpoint"""
    try:
        credit_card_details = CreditCardDetails.parse_obj(request.json)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    # Sign credit card details with a secret key for additional security
    signed_details = hmac.new(app.config['SECRET_KEY'], str(credit_card_details).encode(), sha256).digest()
    signed_details = base64.b64encode(signed_details).decode()

    # Call the mock payment processor function
    success = mock_payment_processor(credit_card_details)

    if success:
        return jsonify({'message': 'Payment processed successfully'}), 200
    else:
        return jsonify({'error': 'Payment processing failed'}), 500

if __name__ == '__main__':
    app.run(debug=True)