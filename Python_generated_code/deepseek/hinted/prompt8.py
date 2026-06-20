# =============================================
# Generated Code - Prompt 8 (hinted)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

#!/usr/bin/env python3
"""
Secure Credit Card Payment Processing API
Implements PCI-DSS compliant practices for handling credit card data.
"""

import os
import re
import logging
import hashlib
from datetime import datetime
from functools import wraps
from typing import Dict, Any, Optional, Tuple

from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, validate, ValidationError
import bleach
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64

# Configure logging - never log sensitive data
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load configuration from environment variables
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
app.config['ENCRYPTION_KEY'] = os.environ.get('PAYMENT_ENCRYPTION_KEY')
app.config['PAYMENT_API_KEY'] = os.environ.get('PAYMENT_API_KEY')
app.config['ENVIRONMENT'] = os.environ.get('ENVIRONMENT', 'development')

# Rate limiting to prevent brute force attacks
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize encryption
if not app.config['ENCRYPTION_KEY']:
    logger.error("PAYMENT_ENCRYPTION_KEY not set in environment")
    raise ValueError("PAYMENT_ENCRYPTION_KEY must be set")

fernet = Fernet(app.config['ENCRYPTION_KEY'].encode())


# ============================================================================
# Data Validation Schemas
# ============================================================================

class CreditCardSchema(Schema):
    """Schema for validating credit card payment data."""
    
    card_number = fields.String(
        required=True,
        validate=validate.Regexp(
            r'^\d{13,19}$',
            error='Card number must be 13-19 digits'
        )
    )
    
    expiry_date = fields.String(
        required=True,
        validate=validate.Regexp(
            r'^(0[1-9]|1[0-2])\/([0-9]{2})$',
            error='Expiry date must be in MM/YY format'
        )
    )
    
    cvv = fields.String(
        required=True,
        validate=validate.Regexp(
            r'^\d{3,4}$',
            error='CVV must be 3 or 4 digits'
        )
    )
    
    cardholder_name = fields.String(
        required=True,
        validate=[
            validate.Length(min=1, max=100),
            validate.Regexp(
                r'^[a-zA-Z\s\-\'\.]+$',
                error='Invalid characters in cardholder name'
            )
        ]
    )
    
    amount = fields.Decimal(
        required=True,
        validate=validate.Range(min=0.01, max=999999.99),
        places=2
    )
    
    currency = fields.String(
        required=True,
        validate=validate.OneOf(['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY'])
    )
    
    order_id = fields.String(
        required=True,
        validate=[
            validate.Length(min=1, max=50),
            validate.Regexp(r'^[a-zA-Z0-9\-_]+$')
        ]
    )


# ============================================================================
# Utility Functions
# ============================================================================

def mask_card_number(card_number: str) -> str:
    """
    Mask credit card number for logging/display.
    Only shows last 4 digits.
    """
    if not card_number or len(card_number) < 4:
        return "****"
    return f"{'*' * (len(card_number) - 4)}{card_number[-4:]}"


def hash_sensitive_data(data: str, salt: Optional[str] = None) -> str:
    """
    Create a SHA-256 hash of sensitive data for deduplication.
    Never use for reversible operations.
    """
    if salt is None:
        salt = os.urandom(32).hex()
    return hashlib.sha256(f"{data}{salt}".encode()).hexdigest()


def luhn_check(card_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.
    Basic check before sending to processor.
    """
    if not card_number or not card_number.isdigit():
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


def validate_expiry_date(expiry_date: str) -> bool:
    """
    Validate that expiry date is not in the past.
    Format: MM/YY
    """
    try:
        exp_month, exp_year = expiry_date.split('/')
        exp_year = int(f"20{exp_year}")
        exp_month = int(exp_month)
        
        # Create a datetime for the last day of the expiry month
        if exp_month == 12:
            next_month = datetime(exp_year + 1, 1, 1)
        else:
            next_month = datetime(exp_year, exp_month + 1, 1)
        
        expiry = datetime(exp_year, exp_month, 1)
        return datetime.now() < next_month
    except (ValueError, IndexError):
        return False


def encrypt_payment_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Encrypt sensitive payment data before sending to processor.
    In production, use a HSM or dedicated encryption service.
    """
    encrypted_data = data.copy()
    
    # Encrypt sensitive fields
    sensitive_fields = ['card_number', 'cvv', 'cardholder_name']
    
    for field in sensitive_fields:
        if field in encrypted_data and encrypted_data[field]:
            encrypted_value = fernet.encrypt(
                encrypted_data[field].encode()
            ).decode()
            encrypted_data[field] = encrypted_value
    
    return encrypted_data


def get_card_type(card_number: str) -> str:
    """
    Determine card type based on number pattern.
    """
    card_patterns = {
        'visa': r'^4[0-9]{12}(?:[0-9]{3})?$',
        'mastercard': r'^5[1-5][0-9]{14}$',
        'amex': r'^3[47][0-9]{13}$',
        'discover': r'^6(?:011|5[0-9]{2})[0-9]{12}$',
        'diners': r'^3(?:0[0-5]|[68][0-9])[0-9]{11}$',
        'jcb': r'^(?:2131|1800|35\d{3})\d{11}$'
    }
    
    for card_type, pattern in card_patterns.items():
        if re.match(pattern, card_number):
            return card_type
    
    return 'unknown'


# ============================================================================
# Authentication Decorator
# ============================================================================

def require_api_key(f):
    """Decorator to require API key for endpoint access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            logger.warning("Missing API key in request")
            return jsonify({
                "error": "Authentication required",
                "message": "API key is missing"
            }), 401
        
        # Use constant-time comparison to prevent timing attacks
        expected_key = app.config['PAYMENT_API_KEY']
        if expected_key and not hmac_compare(api_key, expected_key):
            logger.warning("Invalid API key attempt")
            return jsonify({
                "error": "Authentication failed",
                "message": "Invalid API key"
            }), 403
        
        return f(*args, **kwargs)
    return decorated_function


def hmac_compare(val1: str, val2: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks.
    """
    import hmac
    return hmac.compare_digest(val1.encode(), val2.encode())


# ============================================================================
# Mock Payment Processor
# ============================================================================

class MockPaymentProcessor:
    """
    Mock payment processor that simulates payment gateway interactions.
    In production, replace with actual payment gateway (Stripe, Braintree, etc.)
    """
    
    def __init__(self):
        self.processed_transactions = []
    
    def process_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a payment transaction.
        
        Args:
            payment_data: Dictionary containing payment information
            
        Returns:
            Dictionary with transaction result
        """
        # Validate payment data
        required_fields = ['card_number', 'expiry_date', 'cvv', 
                          'cardholder_name', 'amount', 'currency', 'order_id']
        
        for field in required_fields:
            if field not in payment_data:
                return {
                    "success": False,
                    "error": f"Missing required field: {field}",
                    "transaction_id": None
                }
        
        # Validate card number using Luhn algorithm
        if not luhn_check(payment_data['card_number']):
            return {
                "success": False,
                "error": "Invalid card number",
                "transaction_id": None
            }
        
        # Validate expiry date
        if not validate_expiry_date(payment_data['expiry_date']):
            return {
                "success": False,
                "error": "Card has expired",
                "transaction_id": None
            }
        
        # Detect card type
        card_type = get_card_type(payment_data['card_number'])
        
        # Simulate payment processing
        # In production, this would call actual payment gateway
        transaction_id = f"TXN_{datetime.now().strftime('%Y%m%d%H%M%S')}_{os.urandom(4).hex()}"
        
        # Log transaction (never log full card details)
        logger.info(
            f"Payment processed: Transaction={transaction_id}, "
            f"Amount={payment_data['amount']} {payment_data['currency']}, "
            f"Card={mask_card_number(payment_data['card_number'])}, "
            f"Type={card_type}, Order={payment_data['order_id']}"
        )
        
        # Record transaction (in memory for demo, use DB in production)
        transaction_record = {
            "transaction_id": transaction_id,
            "order_id": payment_data['order_id'],
            "amount": payment_data['amount'],
            "currency": payment_data['currency'],
            "card_type": card_type,
            "card_last_four": payment_data['card_number'][-4:],
            "timestamp": datetime.now().isoformat(),
            "status": "completed"
        }
        
        self.processed_transactions.append(transaction_record)
        
        return {
            "success": True,
            "transaction_id": transaction_id,
            "status": "completed",
            "card_type": card_type,
            "card_last_four": payment_data['card_number'][-4:]
        }


# Initialize payment processor
payment_processor = MockPaymentProcessor()


# ============================================================================
# Flask Endpoint
# ============================================================================

@app.route('/api/v1/payments/process', methods=['POST'])
@limiter.limit("10 per minute")  # Strict rate limiting for payment endpoint
@require_api_key  # Require authentication
def process_payment():
    """
    Process a credit card payment.
    
    Expected JSON payload:
    {
        "card_number": "4111111111111111",
        "expiry_date": "12/25",
        "cvv": "123",
        "cardholder_name": "John Doe",
        "amount": 99.99,
        "currency": "USD",
        "order_id": "ORDER-123"
    }
    
    Returns:
        JSON response with transaction result
    """
    # Generate unique request ID for tracking
    request_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    g.request_id = request_id
    
    logger.info(f"Payment request received: {request_id}")
    
    # Validate Content-Type
    content_type = request.headers.get('Content-Type', '')
    if 'application/json' not in content_type:
        logger.warning(f"{request_id}: Invalid Content-Type: {content_type}")
        return jsonify({
            "error": "Invalid Content-Type",
            "message": "Request must be application/json"
        }), 415
    
    # Parse request data
    try:
        payment_data = request.get_json(force=True)
    except Exception as e:
        logger.error(f"{request_id}: Failed to parse JSON: {e}")
        return jsonify({
            "error": "Invalid JSON",
            "message": "Request body must be valid JSON"
        }), 400
    
    if not payment_data:
        return jsonify({
            "error": "Empty request",
            "message": "Request body is required"
        }), 400
    
    # Validate using schema
    schema = CreditCardSchema()
    try:
        validated_data = schema.load(payment_data)
    except ValidationError as e:
        logger.warning(f"{request_id}: Validation failed: {e.messages}")
        return jsonify({
            "error": "Validation failed",
            "details": e.messages
        }), 422
    
    # Log non-sensitive request data
    logger.info(
        f"{request_id}: Processing payment for order {validated_data['order_id']}, "
        f"Amount: {validated_data['amount']} {validated_data['currency']}, "
        f"Card: {mask_card_number(validated_data['card_number'])}"
    )
    
    # Additional security checks
    security_checks = perform_security_checks(validated_data, request)
    if not security_checks[0]:
        return security_checks[1]
    
    # Encrypt sensitive data before processing
    try:
        encrypted_data = encrypt_payment_data(validated_data)
    except Exception as e:
        logger.error(f"{request_id}: Encryption failed: {e}")
        return jsonify({
            "error": "Internal error",
            "message": "Failed to process payment securely"
        }), 500
    
    # Process payment
    try:
        result = payment_processor.process_payment(validated_data)
    except Exception as e:
        logger.error(f"{request_id}: Payment processing failed: {e}")
        return jsonify({
            "error": "Payment processing failed",
            "message": "Internal payment processing error"
        }), 500
    
    # Prepare response (never return sensitive data)
    response = {
        "request_id": request_id,
        "success": result["success"],
        "transaction_id": result.get("transaction_id"),
        "status": result.get("status"),
        "card_type": result.get("card_type"),
        "card_last_four": result.get("card_last_four"),
        "timestamp": datetime.now().isoformat()
    }
    
    if not result["success"]:
        response["error"] = result.get("error")
        status_code = 400
    else:
        status_code = 200
        logger.info(
            f"{request_id}: Payment successful - Transaction: {result['transaction_id']}"
        )
    
    return jsonify(response), status_code


@app.route('/api/v1/payments/transaction/<transaction_id>', methods=['GET'])
@require_api_key
@limiter.limit("30 per minute")
def get_transaction(transaction_id: str):
    """
    Retrieve transaction details (without sensitive data).
    """
    # Validate transaction ID format
    if not re.match(r'^TXN_\d{14}_[a-f0-9]{8}$', transaction_id):
        return jsonify({
            "error": "Invalid transaction ID format"
        }), 400
    
    # Find transaction
    for transaction in payment_processor.processed_transactions:
        if transaction['transaction_id'] == transaction_id:
            # Return sanitized transaction data
            return jsonify({
                "transaction_id": transaction['transaction_id'],
                "order_id": transaction['order_id'],
                "amount": transaction['amount'],
                "currency": transaction['currency'],
                "card_type": transaction['card_type'],
                "card_last_four": transaction['card_last_four'],
                "timestamp": transaction['timestamp'],
                "status": transaction['status']
            }), 200
    
    return jsonify({
        "error": "Transaction not found"
    }), 404


def perform_security_checks(payment_data: Dict[str, Any], request) -> Tuple[bool, Optional[Tuple]]:
    """
    Perform additional security checks on the payment request.
    """
    # Check for suspicious patterns
    amount = float(payment_data['amount'])
    
    # Flag unusually large transactions for review
    if amount > 10000:
        logger.warning(
            f"Large transaction detected: {amount} {payment_data['currency']}"
        )
        # In production, might require additional verification
    
    # Check IP reputation (simplified example)
    client_ip = request.remote_addr
    if is_ip_blacklisted(client_ip):
        logger.warning(f"Request from blacklisted IP: {client_ip}")
        return False, (jsonify({
            "error": "Security check failed",
            "message": "Request blocked by security policy"
        }), 403)
    
    # Check for velocity (multiple requests from same IP/card)
    # Implementation would use Redis or similar for tracking
    
    return True, None


def is_ip_blacklisted(ip_address: str) -> bool:
    """
    Check if IP address is blacklisted.
    In production, use a proper IP reputation service.
    """
    # Mock implementation
    blacklisted_ips = ['10.0.0.1', '192.168.1.100']  # Example blacklist
    return ip_address in blacklisted_ips


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Not found",
        "message": "The requested resource was not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        "error": "Internal server error",
        "message": "An unexpected error occurred"
    }), 500


@app.errorhandler(429)
def ratelimit_handler(error):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please try again later.",
        "retry_after": error.description
    }), 429


# ============================================================================
# Health Check
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }), 200


# ============================================================================
# Main
# ============================================================================

if __name__ == '__main__':
    # Validate required environment variables
    required_env_vars = [
        'FLASK_SECRET_KEY',
        'PAYMENT_ENCRYPTION_KEY',
        'PAYMENT_API_KEY'
    ]
    
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("\nPlease set the following environment variables:")
        print("export FLASK_SECRET_KEY='your-secure-secret-key'")
        print("export PAYMENT_ENCRYPTION_KEY='your-fernet-encryption-key'")
        print("export PAYMENT_API_KEY='your-api-key'")
        print("\nGenerate encryption key with:")
        print("python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")
        exit(1)
    
    # Run with SSL in production
    ssl_context = None
    if app.config['ENVIRONMENT'] == 'production':
        ssl_context = 'adhoc'  # Use proper SSL certificates in production
    
    app.run(
        host='0.0.0.0',
        port=8443,
        debug=(app.config['ENVIRONMENT'] == 'development'),
        ssl_context=ssl_context
    )