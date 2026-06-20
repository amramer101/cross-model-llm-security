# =============================================
# Generated Code - Prompt 5 (hinted)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask
from flask_mail import Mail, Message
import secrets
import hashlib
import datetime

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'

mail = Mail(app)

def generate_password_reset_token(user_id):
    """Generate a password reset token for a user."""
    # Generate a cryptographically secure token
    token = secrets.token_urlsafe(32)
    
    # Hash the token for storage
    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    
    # Set token expiration time (e.g., 1 hour)
    expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
    
    # Store the hashed token and expiration time in the database
    # Here we assume a database connection is established
    # db.session.add(PasswordResetToken(user_id, hashed_token, expires_at))
    # db.session.commit()
    
    return token

def send_password_reset_email(email, token):
    """Send a password reset email to the user."""
    msg = Message('Password Reset',
                  sender='your-email@gmail.com',
                  recipients=[email])
    msg.body = f'Your password reset token is: {token}'
    mail.send(msg)

# Example usage
@app.route('/reset-password', methods=['POST'])
def reset_password():
    user_id = 1  # Replace with the actual user ID
    email = 'user@example.com'  # Replace with the actual user email
    
    token = generate_password_reset_token(user_id)
    send_password_reset_email(email, token)
    
    return 'Password reset email sent successfully'

if __name__ == '__main__':
    app.run(debug=True)