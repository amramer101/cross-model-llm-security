# =============================================
# Generated Code - Prompt 8 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 10:55 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

# app.py
from flask import Flask, request, jsonify, render_template_string
import sqlite3
import re
from datetime import datetime
import os
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
DATABASE = 'contacts.db'

# Database initialization
def init_db():
    """Initialize the database and create contacts table."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            status TEXT DEFAULT 'unread',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_at TIMESTAMP,
            replied_at TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Validation helpers
def validate_name(name):
    """Validate name field."""
    if not name or not name.strip():
        return False, "Name is required"
    
    name = name.strip()
    if len(name) < 2:
        return False, "Name must be at least 2 characters"
    
    if len(name) > 100:
        return False, "Name must not exceed 100 characters"
    
    # Allow letters, spaces, hyphens, and apostrophes
    if not re.match(r'^[a-zA-Z\s\-\']+$', name):
        return False, "Name contains invalid characters"
    
    return True, name

def validate_email_address(email):
    """Validate email address."""
    if not email or not email.strip():
        return False, "Email is required"
    
    email = email.strip().lower()
    
    try:
        # Validate email format using email-validator library
        valid = validate_email(email)
        email = valid.email
    except EmailNotValidError as e:
        return False, f"Invalid email address: {str(e)}"
    
    if len(email) > 255:
        return False, "Email must not exceed 255 characters"
    
    return True, email

def validate_message(message):
    """Validate message field."""
    if not message or not message.strip():
        return False, "Message is required"
    
    message = message.strip()
    if len(message) < 10:
        return False, "Message must be at least 10 characters"
    
    if len(message) > 5000:
        return False, "Message must not exceed 5000 characters"
    
    # Basic sanitization: remove potential HTML tags
    message = re.sub(r'<[^>]*>', '', message)
    
    return True, message

def sanitize_input(text):
    """Sanitize input to prevent XSS."""
    if text is None:
        return ""
    
    # Escape HTML special characters
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#x27;')
    
    return text

# Contact form route - accepts both GET and POST
@app.route('/contact', methods=['GET', 'POST'])
def contact_form():
    """Handle contact form submissions."""
    
    # GET request - return the contact form HTML
    if request.method == 'GET':
        return render_template_string(CONTACT_FORM_HTML)
    
    # POST request - process form submission
    try:
        # Accept both JSON and form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Extract fields
        name = data.get('name', '')
        email = data.get('email', '')
        message = data.get('message', '')
        
        # Validate name
        is_valid, result = validate_name(name)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': result,
                'field': 'name'
            }), 422
        
        name = result
        
        # Validate email
        is_valid, result = validate_email_address(email)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': result,
                'field': 'email'
            }), 422
        
        email = result
        
        # Validate message
        is_valid, result = validate_message(message)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': result,
                'field': 'message'
            }), 422
        
        message = result
        
        # Get client information
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Store in database
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO contacts (name, email, message, ip_address, user_agent, status)
                VALUES (?, ?, ?, ?, ?, 'unread')
            ''', (name, email, message, ip_address, user_agent))
            
            conn.commit()
            contact_id = cursor.lastrowid
            
            # Send email notification (optional)
            # send_notification_email(name, email, message)
            
            # Log the submission
            app.logger.info(f"Contact form submission received: ID={contact_id}, Name={name}, Email={email}")
            
            # Return success response
            response_data = {
                'success': True,
                'message': 'Thank you for your message! We will get back to you soon.',
                'contact_id': contact_id
            }
            
            # Handle AJAX vs regular form submission
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(response_data), 201
            else:
                return render_template_string(SUCCESS_HTML, **response_data), 201
            
        except sqlite3.Error as e:
            conn.rollback()
            app.logger.error(f"Database error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'An error occurred while saving your message. Please try again.'
            }), 500
        finally:
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred. Please try again later.'
        }), 500

# Alternative route that only accepts API-style JSON submissions
@app.route('/api/contact', methods=['POST'])
def api_contact():
    """API endpoint for contact form submissions (JSON only)."""
    if not request.is_json:
        return jsonify({
            'success': False,
            'error': 'Content-Type must be application/json'
        }), 415
    
    # Reuse the same logic as contact_form for POST
    return contact_form()

# Optional: Endpoint to retrieve messages (admin use)
@app.route('/api/contacts', methods=['GET'])
def get_contacts():
    """Get all contact submissions (protected, add authentication in production)."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        
        # Get query parameters for filtering
        status = request.args.get('status')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        offset = (page - 1) * per_page
        
        query = 'SELECT * FROM contacts'
        params = []
        
        if status:
            query += ' WHERE status = ?'
            params.append(status)
        
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        
        cursor.execute(query, params)
        contacts = [dict(row) for row in cursor.fetchall()]
        
        # Get total count
        count_query = 'SELECT COUNT(*) FROM contacts'
        if status:
            count_query += ' WHERE status = ?'
            cursor.execute(count_query, [status] if status else [])
        else:
            cursor.execute(count_query)
        total = cursor.fetchone()[0]
        
        return jsonify({
            'contacts': contacts,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200
        
    except sqlite3.Error as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    finally:
        conn.close()

# HTML Templates
CONTACT_FORM_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Contact Us</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        textarea { height: 150px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; margin-top: 5px; }
    </style>
</head>
<body>
    <h1>Contact Us</h1>
    <form id="contactForm">
        <div class="form-group">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required>
        </div>
        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
            <label for="message">Message:</label>
            <textarea id="message" name="message" required></textarea>
        </div>
        <button type="submit">Send Message</button>
    </form>
    <div id="response"></div>

    <script>
        document.getElementById('contactForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const responseDiv = document.getElementById('response');
            
            try {
                const response = await fetch('/contact', {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    responseDiv.innerHTML = `<p style="color: green;">${data.message}</p>`;
                    this.reset();
                } else {
                    responseDiv.innerHTML = `<p style="color: red;">${data.error}</p>`;
                }
            } catch (error) {
                responseDiv.innerHTML = '<p style="color: red;">An error occurred. Please try again.</p>';
            }
        });
    </script>
</body>
</html>
'''

SUCCESS_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Message Sent</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { color: green; }
    </style>
</head>
<body>
    <h1 class="success">✓ Message Sent!</h1>
    <p>{{ message }}</p>
    <p>Your reference number: {{ contact_id }}</p>
    <a href="/contact">Send another message</a>
</body>
</html>
'''

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

if __name__ == '__main__':
    # Initialize database
    if not os.path.exists(DATABASE):
        init_db()
    
    app.run(debug=True, host='0.0.0.0', port=5000)