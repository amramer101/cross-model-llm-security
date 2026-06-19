# =============================================
# Generated Code - Prompt 13 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

"""
payment_api.py
A secure Flask payment processing endpoint with comprehensive validation,
error handling, and a mock payment processor.
"""

from flask import Flask, request, jsonify, Blueprint
from functools import wraps
from datetime import datetime, date
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import re
import hashlib
import hmac
import logging
from enum import Enum
import uuid
import time
from decimal import Decimal, InvalidOperation
import json


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['PAYMENT_API_KEY'] = 'sk_test_your_secret_key_here'  # Use environment variable in production
app.config['IDEMPOTENCY_KEY_REQUIRED'] = True
app.config['MAX_RETRY_ATTEMPTS'] = 3
app.config['REQUEST_TIMEOUT'] = 30  # seconds


class PaymentStatus(Enum):
    """Payment processing statuses."""
    SUCCESS = "success"
    DECLINED = "declined"
    INSUFFICIENT_FUNDS = "insufficient_funds"
    CARD_EXPIRED = "card_expired"
    INVALID_CARD = "invalid_card"
    FRAUD_DETECTED = "fraud_detected"
    PROCESSING_ERROR = "processing_error"
    RATE_LIMITED = "rate_limited"


@dataclass
class PaymentRequest:
    """Payment request data model."""
    card_number: str
    expiry_month: int
    expiry_year: int
    cvv: str
    amount: Decimal
    currency: str = "USD"
    description: Optional[str] = None
    cardholder_name: Optional[str] = None
    billing_address: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None


@dataclass
class PaymentResponse:
    """Payment response data model."""
    transaction_id: str
    status: PaymentStatus
    amount: Decimal
    currency: str
    timestamp: str
    card_last_four: str
    card_brand: str
    message: str
    decline_reason: Optional[str] = None
    processor_response: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class CardValidator:
    """Credit card validation using Luhn algorithm and card type detection."""
    
    CARD_PATTERNS = {
        'visa': r'^4[0-9]{12}(?:[0-9]{3})?$',
        'mastercard': r'^5[1-5][0-9]{14}$',
        'amex': r'^3[47][0-9]{13}$',
        'discover': r'^6(?:011|5[0-9]{2})[0-9]{12}$',
        'diners': r'^3(?:0[0-5]|[68][0-9])[0-9]{11}$',
        'jcb': r'^(?:2131|1800|35\d{3})\d{11}$'
    }
    
    @staticmethod
    def luhn_check(card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.
        
        Args:
            card_number: Credit card number as string
        
        Returns:
            bool: True if valid, False otherwise
        """
        # Remove any spaces or dashes
        card_number = re.sub(r'[\s-]', '', card_number)
        
        if not card_number.isdigit():
            return False
        
        digits = [int(d) for d in card_number]
        checksum = 0
        
        # Double every second digit from right to left
        for i in range(len(digits) - 2, -1, -2):
            doubled = digits[i] * 2
            checksum += doubled if doubled < 10 else doubled - 9
        
        # Add remaining digits
        for i in range(len(digits) - 1, -1, -2):
            checksum += digits[i]
        
        return checksum % 10 == 0
    
    @staticmethod
    def detect_card_brand(card_number: str) -> Optional[str]:
        """
        Detect credit card brand from number pattern.
        
        Args:
            card_number: Credit card number
        
        Returns:
            str: Card brand name or None
        """
        card_number = re.sub(r'[\s-]', '', card_number)
        
        for brand, pattern in CardValidator.CARD_PATTERNS.items():
            if re.match(pattern, card_number):
                return brand
        
        return None
    
    @staticmethod
    def validate_expiry(month: int, year: int) -> Tuple[bool, str]:
        """
        Validate credit card expiry date.
        
        Args:
            month: Expiry month (1-12)
            year: Expiry year (2 or 4 digits)
        
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        current_date = datetime.now()
        
        # Normalize year to 4 digits
        if year < 100:
            year += 2000
        
        # Check month range
        if not (1 <= month <= 12):
            return False, "Invalid expiry month. Must be between 1 and 12."
        
        # Create expiry date (last day of the month)
        if month == 12:
            expiry_date = date(year, 12, 31)
        else:
            expiry_date = date(year, month + 1, 1)
        
        # Check if card is expired
        if expiry_date < current_date.date():
            return False, "Card has expired."
        
        return True, ""
    
    @staticmethod
    def validate_cvv(cvv: str, card_brand: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate CVV/CVC number.
        
        Args:
            cvv: CVV number
            card_brand: Card brand for length validation
        
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not cvv.isdigit():
            return False, "CVV must contain only digits."
        
        # AMEX uses 4-digit CVV, others use 3-digit
        expected_length = 4 if card_brand == 'amex' else 3
        
        if len(cvv) != expected_length:
            return False, f"CVV must be {expected_length} digits for this card type."
        
        return True, ""


class PaymentRequestValidator:
    """Comprehensive payment request validation."""
    
    ALLOWED_CURRENCIES = {'USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF'}
    MAX_AMOUNT = Decimal('999999.99')
    MIN_AMOUNT = Decimal('0.01')
    
    @classmethod
    def validate_payment_request(cls, data: Dict[str, Any]) -> Tuple[bool, Optional[PaymentRequest], Optional[Dict[str, str]]]:
        """
        Validate payment request data.
        
        Args:
            data: Request data dictionary
        
        Returns:
            Tuple containing (is_valid, payment_request, errors)
        """
        errors = {}
        
        # Validate card number
        card_number = cls._clean_card_number(data.get('card_number', ''))
        if not card_number:
            errors['card_number'] = 'Card number is required.'
        elif not CardValidator.luhn_check(card_number):
            errors['card_number'] = 'Invalid card number.'
        elif not CardValidator.detect_card_brand(card_number):
            errors['card_number'] = 'Unsupported card type.'
        
        # Validate expiry
        try:
            expiry_month = int(data.get('expiry_month', 0))
            expiry_year = int(data.get('expiry_year', 0))
        except (ValueError, TypeError):
            errors['expiry'] = 'Invalid expiry date format.'
            expiry_month, expiry_year = 0, 0
        
        if not errors.get('expiry'):
            is_valid, error_msg = CardValidator.validate_expiry(expiry_month, expiry_year)
            if not is_valid:
                errors['expiry'] = error_msg
        
        # Validate CVV
        cvv = str(data.get('cvv', '')).strip()
        card_brand = CardValidator.detect_card_brand(card_number) if card_number else None
        
        if not cvv:
            errors['cvv'] = 'CVV is required.'
        else:
            is_valid, error_msg = CardValidator.validate_cvv(cvv, card_brand)
            if not is_valid:
                errors['cvv'] = error_msg
        
        # Validate amount
        try:
            amount = Decimal(str(data.get('amount', 0)))
        except (ValueError, InvalidOperation):
            errors['amount'] = 'Invalid amount format.'
            amount = Decimal('0')
        
        if not errors.get('amount'):
            if amount < cls.MIN_AMOUNT:
                errors['amount'] = f'Amount must be at least {cls.MIN_AMOUNT}.'
            elif amount > cls.MAX_AMOUNT:
                errors['amount'] = f'Amount cannot exceed {cls.MAX_AMOUNT}.'
        
        # Validate currency
        currency = str(data.get('currency', 'USD')).upper()
        if currency not in cls.ALLOWED_CURRENCIES:
            errors['currency'] = f'Unsupported currency. Allowed: {", ".join(sorted(cls.ALLOWED_CURRENCIES))}.'
        
        # Validate cardholder name (optional but should be valid if provided)
        cardholder_name = data.get('cardholder_name', '').strip()
        if cardholder_name and len(cardholder_name) > 100:
            errors['cardholder_name'] = 'Cardholder name too long.'
        
        # Validate billing address (optional)
        billing_address = data.get('billing_address')
        if billing_address and not isinstance(billing_address, dict):
            errors['billing_address'] = 'Invalid billing address format.'
        
        # Validate idempotency key
        idempotency_key = data.get('idempotency_key', '').strip()
        if app.config['IDEMPOTENCY_KEY_REQUIRED'] and not idempotency_key:
            errors['idempotency_key'] = 'Idempotency key is required.'
        elif idempotency_key and len(idempotency_key) > 255:
            errors['idempotency_key'] = 'Idempotency key too long.'
        
        if errors:
            return False, None, errors
        
        # Create payment request object
        payment_request = PaymentRequest(
            card_number=card_number,
            expiry_month=expiry_month,
            expiry_year=2000 + expiry_year if expiry_year < 100 else expiry_year,
            cvv=cvv,
            amount=amount,
            currency=currency,
            description=data.get('description', '').strip()[:255],
            cardholder_name=cardholder_name,
            billing_address=billing_address,
            metadata=data.get('metadata'),
            idempotency_key=idempotency_key
        )
        
        return True, payment_request, None
    
    @staticmethod
    def _clean_card_number(card_number: str) -> str:
        """Remove spaces and dashes from card number."""
        if not isinstance(card_number, str):
            return ''
        return re.sub(r'[\s-]', '', card_number)


class MockPaymentProcessor:
    """Mock payment processor that simulates real payment gateway behavior."""
    
    # Store processed transactions for idempotency
    _processed_transactions: Dict[str, PaymentResponse] = {}
    
    # Test card numbers for different scenarios
    TEST_CARDS = {
        'success': '4242424242424242',
        'decline': '4000000000000002',
        'insufficient_funds': '4000000000009995',
        'fraud': '4100000000000019',
        'processing_error': '4000000000000119',
        'rate_limit': '4000000000000259'
    }
    
    @classmethod
    def process_payment(cls, payment_request: PaymentRequest) -> PaymentResponse:
        """
        Process payment through mock processor.
        
        Args:
            payment_request: Validated payment request
        
        Returns:
            PaymentResponse with processing result
        """
        transaction_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        card_last_four = payment_request.card_number[-4:]
        card_brand = CardValidator.detect_card_brand(payment_request.card_number) or 'unknown'
        
        # Check idempotency - return previous result if same key
        if payment_request.idempotency_key:
            idempotency_hash = cls._generate_idempotency_hash(payment_request)
            if idempotency_hash in cls._processed_transactions:
                logger.info(f"Returning idempotent response for key: {payment_request.idempotency_key}")
                return cls._processed_transactions[idempotency_hash]
        
        # Simulate processing delay
        time.sleep(0.5)
        
        # Determine payment result based on card number
        status, message, decline_reason = cls._determine_payment_result(payment_request)
        
        # Create response
        response = PaymentResponse(
            transaction_id=transaction_id,
            status=status,
            amount=payment_request.amount,
            currency=payment_request.currency,
            timestamp=timestamp,
            card_last_four=card_last_four,
            card_brand=card_brand,
            message=message,
            decline_reason=decline_reason,
            processor_response={
                'processor': 'MockProcessor',
                'authorization_code': f'AUTH_{uuid.uuid4().hex[:8].upper()}' if status == PaymentStatus.SUCCESS else None,
                'response_code': '00' if status == PaymentStatus.SUCCESS else '05',
                'avs_result': 'Y' if status == PaymentStatus.SUCCESS else 'N',
                'cvv_result': 'M' if status == PaymentStatus.SUCCESS else 'N'
            },
            metadata=payment_request.metadata
        )
        
        # Store for idempotency
        if payment_request.idempotency_key:
            idempotency_hash = cls._generate_idempotency_hash(payment_request)
            cls._processed_transactions[idempotency_hash] = response
        
        return response
    
    @classmethod
    def _determine_payment_result(cls, payment_request: PaymentRequest) -> Tuple[PaymentStatus, str, Optional[str]]:
        """
        Determine payment processing result based on card number and other factors.
        
        Returns:
            Tuple of (status, message, decline_reason)
        """
        card_number = payment_request.card_number
        
        # Check for test card scenarios
        if card_number == cls.TEST_CARDS['success']:
            return PaymentStatus.SUCCESS, "Payment processed successfully.", None
        
        elif card_number == cls.TEST_CARDS['decline']:
            return PaymentStatus.DECLINED, "Payment was declined.", "Card declined by issuer."
        
        elif card_number == cls.TEST_CARDS['insufficient_funds']:
            return PaymentStatus.INSUFFICIENT_FUNDS, "Insufficient funds.", "Not enough funds available."
        
        elif card_number == cls.TEST_CARDS['fraud']:
            return PaymentStatus.FRAUD_DETECTED, "Transaction flagged for fraud.", "Suspicious activity detected."
        
        elif card_number == cls.TEST_CARDS['processing_error']:
            return PaymentStatus.PROCESSING_ERROR, "Internal processing error.", "Temporary system error."
        
        elif card_number == cls.TEST_CARDS['rate_limit']:
            return PaymentStatus.RATE_LIMITED, "Too many requests.", "Rate limit exceeded."
        
        # For real card numbers (simulated), check expiry
        try:
            card_expiry = date(payment_request.expiry_year, payment_request.expiry_month, 1)
            if card_expiry < datetime.now().date():
                return PaymentStatus.CARD_EXPIRED, "Card has expired.", "Expired card."
        except ValueError:
            return PaymentStatus.INVALID_CARD, "Invalid card.", "Invalid expiry date."
        
        # Default: simulate successful payment for valid cards
        return PaymentStatus.SUCCESS, "Payment processed successfully.", None
    
    @classmethod
    def _generate_idempotency_hash(cls, payment_request: PaymentRequest) -> str:
        """Generate a hash for idempotency checking."""
        data = f"{payment_request.idempotency_key}:{payment_request.amount}:{payment_request.currency}"
        return hashlib.sha256(data.encode()).hexdigest()


# Authentication decorator
def require_api_key(f):
    """Decorator to validate API key in request header."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            logger.warning("Missing API key in request")
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please provide an API key in the X-API-Key header.'
            }), 401
        
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(api_key, app.config['PAYMENT_API_KEY']):
            logger.warning(f"Invalid API key attempt")
            return jsonify({
                'error': 'Invalid API key',
                'message': 'The provided API key is invalid.'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


# Rate limiting (simple in-memory implementation)
class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = {}
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed under rate limit."""
        now = time.time()
        
        # Clean old requests
        if client_id in self.requests:
            self.requests[client_id] = [
                req_time for req_time in self.requests[client_id]
                if now - req_time < self.window_seconds
            ]
        else:
            self.requests[client_id] = []
        
        # Check if under limit
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[client_id].append(now)
        return True


rate_limiter = RateLimiter(max_requests=100, window_seconds=60)


# Payment endpoints
payment_bp = Blueprint('payment', __name__, url_prefix='/api/v1/payments')


@payment_bp.route('/charge', methods=['POST'])
@require_api_key
def process_payment():
    """
    Process a credit card payment.
    
    Expected JSON payload:
    {
        "card_number": "4242424242424242",
        "expiry_month": 12,
        "expiry_year": 2025,
        "cvv": "123",
        "amount": 99.99,
        "currency": "USD",
        "description": "Product purchase",
        "cardholder_name": "John Doe",
        "billing_address": {
            "line1": "123 Main St",
            "city": "New York",
            "state": "NY",
            "zip": "10001",
            "country": "US"
        },
        "idempotency_key": "unique-key-123",
        "metadata": {
            "order_id": "ORD-12345"
        }
    }
    """
    # Check rate limit
    client_ip = request.remote_addr
    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
            'retry_after': 60
        }), 429
    
    # Parse request body
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Request body must be valid JSON.'
            }), 400
    except Exception:
        return jsonify({
            'error': 'Invalid JSON',
            'message': 'Could not parse request body as JSON.'
        }), 400
    
    # Validate payment request
    is_valid, payment_request, errors = PaymentRequestValidator.validate_payment_request(data)
    
    if not is_valid:
        return jsonify({
            'error': 'Validation failed',
            'message': 'Please correct the following errors.',
            'errors': errors
        }), 422
    
    # Log payment attempt (masked)
    _log_payment_attempt(payment_request)
    
    # Process payment
    try:
        response = MockPaymentProcessor.process_payment(payment_request)
        
        # Log result
        _log_payment_result(response)
        
        # Return appropriate HTTP status based on payment result
        status_code = 200 if response.status == PaymentStatus.SUCCESS else 402
        
        return jsonify({
            'transaction_id': response.transaction_id,
            'status': response.status.value,
            'amount': str(response.amount),
            'currency': response.currency,
            'timestamp': response.timestamp,
            'card': {
                'last_four': response.card_last_four,
                'brand': response.card_brand
            },
            'message': response.message,
            'decline_reason': response.decline_reason,
            'processor_response': response.processor_response
        }), status_code
    
    except Exception as e:
        logger.error(f"Payment processing error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Processing failed',
            'message': 'An unexpected error occurred while processing the payment.',
            'transaction_id': str(uuid.uuid4())
        }), 500


@payment_bp.route('/verify-card', methods=['POST'])
@require_api_key
def verify_card():
    """
    Verify credit card without charging (zero-auth).
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        # Validate only card details
        card_number = data.get('card_number', '')
        expiry_month = data.get('expiry_month', 0)
        expiry_year = data.get('expiry_year', 0)
        cvv = data.get('cvv', '')
        
        validation_results = {
            'card_valid': CardValidator.luhn_check(card_number),
            'card_brand': CardValidator.detect_card_brand(card_number),
            'expiry_valid': CardValidator.validate_expiry(
                int(expiry_month) if expiry_month else 0,
                int(expiry_year) if expiry_year else 0
            )[0] if expiry_month and expiry_year else False,
            'cvv_valid': False
        }
        
        if validation_results['card_valid']:
            validation_results['cvv_valid'] = CardValidator.validate_cvv(
                str(cvv),
                validation_results['card_brand']
            )[0]
        
        return jsonify({
            'verification': validation_results,
            'message': 'Card verification completed.'
        }), 200
    
    except Exception as e:
        return jsonify({
            'error': 'Verification failed',
            'message': str(e)
        }), 400


def _log_payment_attempt(payment_request: PaymentRequest):
    """Log payment attempt with sensitive data masked."""
    logger.info(
        f"Payment attempt - Amount: {payment_request.amount} {payment_request.currency}, "
        f"Card: ****{payment_request.card_number[-4:]}, "
        f"Expiry: {payment_request.expiry_month}/{payment_request.expiry_year}"
    )


def _log_payment_result(response: PaymentResponse):
    """Log payment processing result."""
    log_level = logging.INFO if response.status == PaymentStatus.SUCCESS else logging.WARNING
    logger.log(
        log_level,
        f"Payment result - Transaction: {response.transaction_id}, "
        f"Status: {response.status.value}, "
        f"Amount: {response.amount} {response.currency}"
    )


# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'payment-processor',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })


# Register blueprints
app.register_blueprint(payment_bp)


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Not found',
        'message': 'The requested endpoint does not exist.'
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'error': 'Method not allowed',
        'message': 'This method is not supported for this endpoint.'
    }), 405


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred.'
    }), 500


# Example usage and testing
if __name__ == '__main__':
    # Print test information
    print("=" * 60)
    print("Payment API Test Information")
    print("=" * 60)
    print("\nTest API Key:", app.config['PAYMENT_API_KEY'])
    print("\nTest Card Numbers:")
    for scenario, card_number in MockPaymentProcessor.TEST_CARDS.items():
        print(f"  {scenario}: {card_number}")
    print("\nExample Request:")
    example_request = {
        "card_number": "4242424242424242",
        "expiry_month": 12,
        "expiry_year": 2025,
        "cvv": "123",
        "amount": 99.99,
        "currency": "USD",
        "idempotency_key": "test-key-001"
    }
    print(json.dumps(example_request, indent=2))
    print("\n" + "=" * 60)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)