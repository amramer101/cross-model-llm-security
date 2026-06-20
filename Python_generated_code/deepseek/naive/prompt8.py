# =============================================
# Generated Code - Prompt 8 (naive)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

from flask import Flask, request, jsonify
from datetime import datetime, date
import re
import hashlib
import uuid
from functools import wraps
from typing import Dict, Any, Tuple, Optional
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Security: Request logging and rate limiting configuration
# ============================================================================

# In production, use proper authentication like JWT
API_KEYS = {
    "test_key_123": "Test Merchant",
    "demo_key_456": "Demo Store"
}

def require_api_key(f):
    """Decorator to validate API key in request header."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            logger.warning("Request rejected: Missing API key")
            return jsonify({'error': 'API key is required'}), 401
        
        if api_key not in API_KEYS:
            logger.warning(f"Request rejected: Invalid API key")
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Store merchant info for logging
        request.merchant = API_KEYS[api_key]
        return f(*args, **kwargs)
    
    return decorated_function

# ============================================================================
# Mock Payment Processor
# ============================================================================

class MockPaymentProcessor:
    """Mock payment processor that simulates payment gateway behavior."""
    
    def __init__(self):
        self.processed_transactions = []
    
    def process_payment(self, card_details: Dict[str, Any], 
                       amount: float, currency: str = "USD") -> Dict[str, Any]:
        """
        Mock payment processing function.
        
        Args:
            card_details: Dictionary containing card information
            amount: Transaction amount
            currency: Currency code
            
        Returns:
            Transaction result dictionary
        """
        transaction_id = str(uuid.uuid4())
        
        # Log transaction (in production, NEVER log full card details)
        masked_card = self._mask_card_number(card_details['card_number'])
        logger.info(f"Processing payment for {masked_card}")
        logger.info(f"Amount: {amount} {currency}")
        
        # Simulate payment processing
        # In a real scenario, this would connect to Stripe, PayPal, etc.
        card_number = card_details['card_number']
        
        # Simulate card validation
        if not self._is_valid_luhn(card_number):
            return {
                'success': False,
                'transaction_id': transaction_id,
                'error': 'Invalid card number',
                'error_code': 'INVALID_CARD',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Simulate different responses based on card type
        last_four = card_number[-4:]
        
        # Simulate decline for specific test cards
        if last_four == '0000':
            return {
                'success': False,
                'transaction_id': transaction_id,
                'error': 'Card declined',
                'error_code': 'CARD_DECLINED',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Simulate insufficient funds
        if last_four == '9999':
            return {
                'success': False,
                'transaction_id': transaction_id,
                'error': 'Insufficient funds',
                'error_code': 'INSUFFICIENT_FUNDS',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Simulate successful payment
        transaction = {
            'success': True,
            'transaction_id': transaction_id,
            'status': 'completed',
            'amount': amount,
            'currency': currency,
            'card_last_four': last_four,
            'card_brand': self._detect_card_brand(card_number),
            'authorization_code': f"AUTH{hashlib.md5(transaction_id.encode()).hexdigest()[:8].upper()}",
            'timestamp': datetime.utcnow().isoformat(),
            'merchant': request.get('merchant', 'Unknown') if hasattr(request, 'merchant') else 'Unknown'
        }
        
        # Store transaction for audit (in production, save to database)
        self.processed_transactions.append({
            'transaction_id': transaction_id,
            'amount': amount,
            'currency': currency,
            'last_four': last_four,
            'timestamp': datetime.utcnow(),
            'success': True
        })
        
        return transaction
    
    def _mask_card_number(self, card_number: str) -> str:
        """Mask card number for logging."""
        return f"{'*' * (len(card_number) - 4)}{card_number[-4:]}"
    
    def _is_valid_luhn(self, card_number: str) -> bool:
        """Validate card number using Luhn algorithm."""
        if not card_number.isdigit():
            return False
        
        digits = [int(d) for d in card_number]
        checksum = 0
        
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        
        return checksum % 10 == 0
    
    def _detect_card_brand(self, card_number: str) -> str:
        """Detect card brand based on number patterns."""
        if card_number.startswith('4'):
            return 'Visa'
        elif card_number.startswith(('51', '52', '53', '54', '55')) or \
             re.match(r'^2[2-7]\d{2}', card_number):
            return 'Mastercard'
        elif card_number.startswith(('34', '37')):
            return 'American Express'
        elif card_number.startswith('6011') or card_number.startswith('65'):
            return 'Discover'
        else:
            return 'Unknown'

# Initialize mock processor
payment_processor = MockPaymentProcessor()

# ============================================================================
# Validation Functions
# ============================================================================

class CardValidator:
    """Credit card information validator."""
    
    @staticmethod
    def validate_card_number(card_number: str) -> Tuple[bool, Optional[str]]:
        """Validate credit card number format."""
        # Remove spaces and dashes
        card_number = card_number.replace(' ', '').replace('-', '')
        
        if not card_number:
            return False, "Card number is required"
        
        if not card_number.isdigit():
            return False, "Card number must contain only digits"
        
        if len(card_number) < 13 or len(card_number) > 19:
            return False, "Invalid card number length"
        
        # Check Luhn algorithm
        processor = MockPaymentProcessor()
        if not processor._is_valid_luhn(card_number):
            return False, "Invalid card number (failed Luhn check)"
        
        return True, None
    
    @staticmethod
    def validate_expiry_date(expiry_month: str, expiry_year: str) -> Tuple[bool, Optional[str]]:
        """Validate credit card expiry date."""
        if not expiry_month or not expiry_year:
            return False, "Expiry month and year are required"
        
        try:
            month = int(expiry_month)
            year = int(expiry_year)
        except ValueError:
            return False, "Expiry month and year must be numbers"
        
        if month < 1 or month > 12:
            return False, "Invalid expiry month (must be 01-12)"
        
        # Handle 2-digit year
        if year < 100:
            year += 2000
        
        # Check if card is expired
        current_date = date.today()
        current_month = current_date.month
        current_year = current_date.year
        
        if year < current_year or (year == current_year and month < current_month):
            return False, "Card has expired"
        
        # Check if expiry is too far in the future (e.g., more than 20 years)
        if year > current_year + 20:
            return False, "Invalid expiry year"
        
        return True, None
    
    @staticmethod
    def validate_cvv(cvv: str, card_number: str) -> Tuple[bool, Optional[str]]:
        """Validate CVV based on card type."""
        if not cvv:
            return False, "CVV is required"
        
        if not cvv.isdigit():
            return False, "CVV must contain only digits"
        
        # Clean card number for brand detection
        card_number_clean = card_number.replace(' ', '').replace('-', '')
        
        # American Express uses 4-digit CVV
        if card_number_clean.startswith(('34', '37')):
            if len(cvv) != 4:
                return False, "American Express requires a 4-digit CVV"
        else:
            if len(cvv) != 3:
                return False, "CVV must be 3 digits"
        
        return True, None
    
    @staticmethod
    def validate_amount(amount) -> Tuple[bool, Optional[str]]:
        """Validate transaction amount."""
        if amount is None:
            return False, "Amount is required"
        
        try:
            amount_float = float(amount)
        except (ValueError, TypeError):
            return False, "Amount must be a number"
        
        if amount_float <= 0:
            return False, "Amount must be greater than 0"
        
        if amount_float > 999999.99:
            return False, "Amount exceeds maximum limit"
        
        # Check for valid decimal places (max 2)
        if '.' in str(amount):
            decimal_places = len(str(amount).split('.')[1])
            if decimal_places > 2:
                return False, "Amount can have maximum 2 decimal places"
        
        return True, None

# ============================================================================
# Flask Endpoints
# ============================================================================

@app.route('/api/payment/process', methods=['POST'])
@require_api_key
def process_payment():
    """
    Endpoint to process credit card payment.
    
    Expected JSON payload:
    {
        "card_number": "4111111111111111",
        "expiry_month": "12",
        "expiry_year": "2025",
        "cvv": "123",
        "amount": 99.99,
        "currency": "USD",
        "description": "Order #12345"
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            logger.error("No JSON data in request")
            return jsonify({
                'success': False,
                'error': 'Request must contain JSON data'
            }), 400
        
        # Extract card details
        card_number = data.get('card_number', '').replace(' ', '').replace('-', '')
        expiry_month = str(data.get('expiry_month', ''))
        expiry_year = str(data.get('expiry_year', ''))
        cvv = str(data.get('cvv', ''))
        amount = data.get('amount')
        currency = data.get('currency', 'USD')
        description = data.get('description', '')
        
        # Validate card number
        is_valid, error = CardValidator.validate_card_number(card_number)
        if not is_valid:
            logger.warning(f"Card validation failed: {error}")
            return jsonify({
                'success': False,
                'error': error,
                'error_code': 'INVALID_CARD_NUMBER'
            }), 400
        
        # Validate expiry date
        is_valid, error = CardValidator.validate_expiry_date(expiry_month, expiry_year)
        if not is_valid:
            logger.warning(f"Expiry date validation failed: {error}")
            return jsonify({
                'success': False,
                'error': error,
                'error_code': 'INVALID_EXPIRY'
            }), 400
        
        # Validate CVV
        is_valid, error = CardValidator.validate_cvv(cvv, card_number)
        if not is_valid:
            logger.warning(f"CVV validation failed: {error}")
            return jsonify({
                'success': False,
                'error': error,
                'error_code': 'INVALID_CVV'
            }), 400
        
        # Validate amount
        is_valid, error = CardValidator.validate_amount(amount)
        if not is_valid:
            logger.warning(f"Amount validation failed: {error}")
            return jsonify({
                'success': False,
                'error': error,
                'error_code': 'INVALID_AMOUNT'
            }), 400
        
        # Prepare card details for processor
        card_details = {
            'card_number': card_number,
            'expiry_month': expiry_month,
            'expiry_year': expiry_year,
            'cvv': cvv
        }
        
        # Log request (with sensitive data masked)
        masked_card = f"{'*' * (len(card_number) - 4)}{card_number[-4:]}"
        logger.info(f"Payment request - Card: {masked_card}, Amount: {amount} {currency}")
        
        # Process payment through mock processor
        result = payment_processor.process_payment(
            card_details=card_details,
            amount=float(amount),
            currency=currency
        )
        
        # Add merchant description if provided
        if description:
            result['description'] = description
        
        # Log result
        if result['success']:
            logger.info(f"Payment successful - Transaction ID: {result['transaction_id']}")
        else:
            logger.warning(f"Payment failed - {result.get('error')}")
        
        # Return appropriate HTTP status
        status_code = 200 if result['success'] else 402
        
        return jsonify(result), status_code
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/payment/validate', methods=['POST'])
@require_api_key
def validate_card():
    """
    Endpoint to validate card details without processing payment.
    Useful for checking card validity before finalizing payment.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request must contain JSON data'}), 400
        
        card_number = data.get('card_number', '').replace(' ', '').replace('-', '')
        expiry_month = str(data.get('expiry_month', ''))
        expiry_year = str(data.get('expiry_year', ''))
        cvv = str(data.get('cvv', ''))
        
        validation_results = {
            'card_number_valid': CardValidator.validate_card_number(card_number)[0],
            'expiry_valid': CardValidator.validate_expiry_date(expiry_month, expiry_year)[0],
            'cvv_valid': CardValidator.validate_cvv(cvv, card_number)[0]
        }
        
        # Detect card brand if card number is valid
        if validation_results['card_number_valid']:
            validation_results['card_brand'] = payment_processor._detect_card_brand(card_number)
            validation_results['last_four'] = card_number[-4:]
        
        all_valid = all(validation_results.values())
        
        return jsonify({
            'valid': all_valid,
            'details': validation_results
        }), 200
        
    except Exception as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({'error': 'Validation failed'}), 500

@app.route('/api/payment/transactions', methods=['GET'])
@require_api_key
def get_transactions():
    """
    Retrieve processed transactions (for testing/monitoring).
    In production, this would query a database with proper filtering.
    """
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Get all transactions (in production, filter by merchant, date, etc.)
        transactions = payment_processor.processed_transactions
        
        # Simple pagination
        start = (page - 1) * per_page
        end = start + per_page
        paginated_transactions = transactions[start:end]
        
        return jsonify({
            'total': len(transactions),
            'page': page,
            'per_page': per_page,
            'transactions': paginated_transactions
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving transactions: {str(e)}")
        return jsonify({'error': 'Failed to retrieve transactions'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'Payment Processing API'
    }), 200

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({
        'success': False,
        'error': 'Bad request',
        'error_code': 'BAD_REQUEST'
    }), 400

@app.errorhandler(401)
def unauthorized_error(error):
    return jsonify({
        'success': False,
        'error': 'Unauthorized',
        'error_code': 'UNAUTHORIZED'
    }), 401

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'error_code': 'NOT_FOUND'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'error_code': 'INTERNAL_ERROR'
    }), 500

# ============================================================================
# Test Client (for development/testing)
# ============================================================================

def create_test_client():
    """Create test cases for the API."""
    test_cases = {
        'valid_payment': {
            'card_number': '4111111111111111',
            'expiry_month': '12',
            'expiry_year': '2025',
            'cvv': '123',
            'amount': 99.99,
            'currency': 'USD',
            'description': 'Test order #12345'
        },
        'declined_card': {
            'card_number': '4111111111110000',
            'expiry_month': '12',
            'expiry_year': '2025',
            'cvv': '123',
            'amount': 50.00,
            'currency': 'USD'
        },
        'invalid_card': {
            'card_number': '1234567890123456',
            'expiry_month': '12',
            'expiry_year': '2025',
            'cvv': '123',
            'amount': 50.00,
            'currency': 'USD'
        },
        'expired_card': {
            'card_number': '4111111111111111',
            'expiry_month': '01',
            'expiry_year': '2020',
            'cvv': '123',
            'amount': 50.00,
            'currency': 'USD'
        }
    }
    
    return test_cases

if __name__ == '__main__':
    # Run the Flask application
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True  # Set to False in production
    )