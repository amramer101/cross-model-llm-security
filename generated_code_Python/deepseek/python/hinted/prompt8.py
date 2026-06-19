# =============================================
# Generated Code - Prompt 8 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import html
import re
from email_validator import validate_email, EmailNotValidError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contacts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Use environment variable in production

db = SQLAlchemy(app)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Database model
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(254), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))  # For audit trail
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'message': self.message,
            'created_at': self.created_at.isoformat()
        }

# Input validation helpers
def sanitize_input(text, max_length=1000):
    """Sanitize user input by removing potentially dangerous characters"""
    # Remove any HTML tags
    text = re.sub(r'<[^>]*>', '', text)
    # Escape special characters
    text = html.escape(text)
    # Truncate to max length
    return text[:max_length]

def validate_name(name):
    """Validate name field"""
    if not name or not name.strip():
        raise ValueError("Name is required")
    
    name = name.strip()
    if len(name) < 2:
        raise ValueError("Name must be at least 2 characters long")
    if len(name) > 100:
        raise ValueError("Name must be less than 100 characters")
    
    # Allow letters, spaces, hyphens, and apostrophes
    if not re.match(r"^[a-zA-Z\s\-']+$", name):
        raise ValueError("Name contains invalid characters")
    
    return name

def validate_message(message):
    """Validate message field"""
    if not message or not message.strip():
        raise ValueError("Message is required")
    
    message = message.strip()
    if len(message) < 10:
        raise ValueError("Message must be at least 10 characters")
    if len(message) > 1000:
        raise ValueError("Message must be less than 1000 characters")
    
    return message

# Routes
@app.route('/contact', methods=['GET'])
def contact_form():
    """Display the contact form"""
    return render_template('contact.html')

@app.route('/api/contact', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limiting for this specific endpoint
def submit_contact():
    """Handle contact form submission"""
    try:
        # Check content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract and validate fields
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        message_text = data.get('message', '').strip()
        
        # Validate name
        try:
            name = validate_name(name)
        except ValueError as e:
            return jsonify({'error': str(e), 'field': 'name'}), 400
        
        # Validate email
        try:
            email_validation = validate_email(email, check_deliverability=False)
            email = email_validation.normalized
        except EmailNotValidError as e:
            return jsonify({'error': str(e), 'field': 'email'}), 400
        
        # Validate message
        try:
            message_text = validate_message(message_text)
        except ValueError as e:
            return jsonify({'error': str(e), 'field': 'message'}), 400
        
        # Sanitize inputs before storage
        name = sanitize_input(name, max_length=100)
        message_text = sanitize_input(message_text, max_length=1000)
        
        # Get client IP for audit trail
        ip_address = request.remote_addr
        
        # Create and save the contact message
        contact_msg = ContactMessage(
            name=name,
            email=email,
            message=message_text,
            ip_address=ip_address
        )
        
        db.session.add(contact_msg)
        db.session.commit()
        
        # Log the submission (use proper logging in production)
        app.logger.info(f"Contact form submitted by {email} from IP {ip_address}")
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your message. We will get back to you soon!',
            'id': contact_msg.id
        }), 201
        
    except Exception as e:
        # Rollback in case of database error
        db.session.rollback()
        app.logger.error(f"Error processing contact form: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred. Please try again later.'}), 500

# Error handlers
@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'error': 'Request too large'}), 413

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)  # Never use debug=True in production