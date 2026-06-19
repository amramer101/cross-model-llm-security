# =============================================
# Generated Code - Prompt 10 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import uuid
from typing import Optional, Dict

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a secure random key
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session expires after 2 hours
app.config['SESSION_COOKIE_NAME'] = 'app_session'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Refresh session on each request

# Mock user database (replace with real database in production)
USERS_DB = {
    'john_doe': {
        'id': '1',
        'username': 'john_doe',
        'password_hash': generate_password_hash('password123'),
        'email': 'john@example.com',
        'role': 'user',
        'created_at': datetime.utcnow().isoformat()
    },
    'admin': {
        'id': '2',
        'username': 'admin',
        'password_hash': generate_password_hash('admin123'),
        'email': 'admin@example.com',
        'role': 'admin',
        'created_at': datetime.utcnow().isoformat()
    }
}

# In-memory session store (use Redis or database in production)
ACTIVE_SESSIONS = {}


class SessionManager:
    """Manages user sessions with additional security features."""
    
    @staticmethod
    def create_session(user_data: Dict) -> str:
        """
        Create a new user session.
        
        Args:
            user_data: Dictionary containing user information
        
        Returns:
            session_id: Unique session identifier
        """
        session_id = str(uuid.uuid4())
        
        session_data = {
            'session_id': session_id,
            'user_id': user_data['id'],
            'username': user_data['username'],
            'email': user_data['email'],
            'role': user_data['role'],
            'login_time': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string,
            'is_active': True
        }
        
        # Store session data
        ACTIVE_SESSIONS[session_id] = session_data
        
        # Store minimal info in Flask session
        session.permanent = True
        session['session_id'] = session_id
        session['user_id'] = user_data['id']
        session['username'] = user_data['username']
        session['role'] = user_data['role']
        session['login_time'] = datetime.utcnow().isoformat()
        
        return session_id
    
    @staticmethod
    def validate_session() -> bool:
        """
        Validate the current session.
        
        Returns:
            bool: True if session is valid, False otherwise
        """
        session_id = session.get('session_id')
        
        if not session_id:
            return False
        
        if session_id not in ACTIVE_SESSIONS:
            return False
        
        session_data = ACTIVE_SESSIONS[session_id]
        
        # Check if session is active
        if not session_data['is_active']:
            return False
        
        # Check for session hijacking (IP/user-agent change)
        if session_data['ip_address'] != request.remote_addr:
            # In production, you might want to be more lenient with mobile users
            SessionManager.destroy_session(session_id)
            return False
        
        # Update last activity timestamp
        session_data['last_activity'] = datetime.utcnow().isoformat()
        
        return True
    
    @staticmethod
    def destroy_session(session_id: Optional[str] = None):
        """
        Destroy a user session.
        
        Args:
            session_id: Optional specific session ID to destroy
        """
        if session_id is None:
            session_id = session.get('session_id')
        
        if session_id and session_id in ACTIVE_SESSIONS:
            ACTIVE_SESSIONS[session_id]['is_active'] = False
            del ACTIVE_SESSIONS[session_id]
        
        # Clear Flask session
        session.clear()
    
    @staticmethod
    def get_user_sessions(user_id: str) -> list:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID to look up
        
        Returns:
            list: List of active sessions
        """
        return [
            session_data 
            for session_data in ACTIVE_SESSIONS.values()
            if session_data['user_id'] == user_id and session_data['is_active']
        ]


# Decorators for authentication and authorization

def login_required(f):
    """Decorator to require user login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SessionManager.validate_session():
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SessionManager.validate_session():
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    """Decorator for API routes that returns JSON instead of redirecting."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SessionManager.validate_session():
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to access this endpoint'
            }), 401
        return f(*args, **kwargs)
    return decorated_function


# Routes

@app.route('/')
def home():
    """Home page route."""
    if SessionManager.validate_session():
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route with session creation."""
    # Redirect if already logged in
    if SessionManager.validate_session():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'
        
        # Validate input
        if not username or not password:
            flash('Please provide both username and password.', 'danger')
            return render_template('login.html')
        
        # Check user credentials
        user = USERS_DB.get(username)
        
        if not user:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')
        
        if not check_password_hash(user['password_hash'], password):
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')
        
        # Create session
        SessionManager.create_session(user)
        
        if remember_me:
            # Extend session lifetime for "remember me"
            app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
        
        flash(f'Welcome back, {username}!', 'success')
        
        # Redirect to originally requested page or dashboard
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout route with session destruction."""
    username = session.get('username', 'User')
    SessionManager.destroy_session()
    flash(f'Goodbye, {username}! You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Protected dashboard route."""
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         role=session.get('role'),
                         login_time=session.get('login_time'))


@app.route('/profile')
@login_required
def profile():
    """Protected profile route."""
    user = USERS_DB.get(session.get('username', ''))
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get active sessions for the user
    active_sessions = SessionManager.get_user_sessions(user['id'])
    
    return render_template('profile.html',
                         user=user,
                         active_sessions=active_sessions)


@app.route('/admin')
@admin_required
def admin_panel():
    """Admin-only route."""
    return render_template('admin.html', 
                         username=session.get('username'),
                         active_sessions=ACTIVE_SESSIONS)


# API routes

@app.route('/api/session/status')
@api_login_required
def session_status():
    """API endpoint to check session status."""
    return jsonify({
        'status': 'active',
        'username': session.get('username'),
        'role': session.get('role'),
        'login_time': session.get('login_time'),
        'session_id': session.get('session_id')
    })


@app.route('/api/session/destroy-all', methods=['POST'])
@api_login_required
def destroy_all_sessions():
    """API endpoint to destroy all sessions for the current user."""
    user_id = session.get('user_id')
    user_sessions = SessionManager.get_user_sessions(user_id)
    
    for sess in user_sessions:
        SessionManager.destroy_session(sess['session_id'])
    
    flash('All other sessions have been terminated.', 'info')
    return jsonify({
        'message': 'All sessions destroyed successfully',
        'sessions_terminated': len(user_sessions)
    })


# Error handlers

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    SessionManager.destroy_session()
    return render_template('500.html'), 500


# Context processor to add user info to all templates
@app.context_processor
def inject_user():
    """Inject user information into all templates."""
    if SessionManager.validate_session():
        return {
            'current_user': {
                'username': session.get('username'),
                'role': session.get('role'),
                'is_authenticated': True
            }
        }
    return {
        'current_user': {
            'is_authenticated': False
        }
    }


# Template for the application (save as templates/home.html)
home_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Home - Flask Session Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .flash-messages { margin: 20px 0; }
        .flash { padding: 10px; margin: 5px 0; border-radius: 5px; }
        .success { background-color: #d4edda; color: #155724; }
        .danger { background-color: #f8d7da; color: #721c24; }
        .warning { background-color: #fff3cd; color: #856404; }
        .info { background-color: #d1ecf1; color: #0c5460; }
    </style>
</head>
<body>
    <h1>Welcome to Flask Session Demo</h1>
    
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            <div class="flash-messages">
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    
    {% if current_user.is_authenticated %}
        <p>Welcome, {{ current_user.username }}!</p>
        <p><a href="{{ url_for('dashboard') }}">Go to Dashboard</a></p>
        <p><a href="{{ url_for('logout') }}">Logout</a></p>
    {% else %}
        <p>Please <a href="{{ url_for('login') }}">login</a> to continue.</p>
    {% endif %}
</body>
</html>
"""


if __name__ == '__main__':
    # Create templates directory and save template files
    import os
    os.makedirs('templates', exist_ok=True)
    
    # Save home template
    with open('templates/home.html', 'w') as f:
        f.write(home_template)
    
    # Start the application
    app.run(debug=True, ssl_context='adhoc')  # Use SSL in production