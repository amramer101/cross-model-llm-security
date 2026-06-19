# =============================================
# Generated Code - Prompt 10 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

import os
import secrets
import hashlib
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Dict, Any
from dataclasses import dataclass

from flask import (
    Flask, request, jsonify, session, g, 
    render_template, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import redis
import logging
from logging.handlers import RotatingFileHandler

# ============================================================================
# Application Setup
# ============================================================================

app = Flask(__name__)

# Configuration from environment variables
class Config:
    """Application configuration with secure defaults"""
    # Secret keys
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    SESSION_COOKIE_NAME = '__Host-session'  # Prefix with __Host- for added security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True  # Only send over HTTPS
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_PATH = '/'
    SESSION_COOKIE_DOMAIN = None  # Don't set domain for __Host- prefix
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_REFRESH_EACH_REQUEST = True
    SESSION_USE_SIGNER = True
    
    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
    
    # Redis for session storage (production)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Session timeout settings
    SESSION_IDLE_TIMEOUT = 30 * 60  # 30 minutes
    SESSION_ABSOLUTE_TIMEOUT = 4 * 60 * 60  # 4 hours
    REMEMBER_ME_TIMEOUT = 7 * 24 * 60 * 60  # 7 days

app.config.from_object(Config)

# Security headers with Talisman
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self' 'unsafe-inline'",
    },
    content_security_policy_nonce_in=['script-src'],
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    x_content_type_options=True,
    x_frame_options='DENY',
    x_xss_protection=True,
    referrer_policy='strict-origin-when-cross-origin'
)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get('REDIS_URL', 'memory://')
)

# Proxy fix for proper IP handling behind reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Database
db = SQLAlchemy(app)

# Redis for session storage
redis_client = redis.from_url(app.config['REDIS_URL'], decode_responses=True)

# Logging setup
if not app.debug:
    handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=5)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

# ============================================================================
# Database Models
# ============================================================================

class User(db.Model):
    """User model with secure password handling"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, password: str):
        """Hash password using werkzeug's security functions"""
        self.password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256:260000',  # Strong hashing
            salt_length=16
        )
    
    def check_password(self, password: str) -> bool:
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary (excluding sensitive data)"""
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'email_verified': self.email_verified
        }

class SessionRecord(db.Model):
    """Track active sessions in database for additional security"""
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    device_info = db.Column(db.String(256))
    
    user = db.relationship('User', backref='sessions')
    
    def is_expired(self) -> bool:
        """Check if session has expired"""
        return datetime.utcnow() > self.expires_at

# ============================================================================
# Session Manager
# ============================================================================

class SessionManager:
    """Secure session management handler"""
    
    @staticmethod
    def create_session(user_id: int, remember_me: bool = False) -> str:
        """Create a new user session"""
        # Generate secure session ID
        session_id = secrets.token_hex(32)
        
        # Get client information
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')[:256]
        device_info = SessionManager._get_device_info()
        
        # Calculate expiration
        now = datetime.utcnow()
        if remember_me:
            expires_at = now + timedelta(seconds=app.config['REMEMBER_ME_TIMEOUT'])
        else:
            expires_at = now + timedelta(seconds=app.config['SESSION_ABSOLUTE_TIMEOUT'])
        
        # Store session in database
        session_record = SessionRecord(
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
            device_info=device_info
        )
        
        db.session.add(session_record)
        db.session.commit()
        
        # Store session in Redis for fast access
        session_data = {
            'user_id': user_id,
            'session_id': session_id,
            'ip_address': ip_address,
            'expires_at': expires_at.isoformat(),
            'remember_me': remember_me
        }
        
        redis_client.hset(
            f"session:{session_id}",
            mapping=session_data
        )
        redis_client.expire(f"session:{session_id}", app.config['SESSION_ABSOLUTE_TIMEOUT'])
        
        # Set Flask session
        session.permanent = True
        session['session_id'] = session_id
        session['user_id'] = user_id
        session['login_time'] = datetime.utcnow().isoformat()
        session['ip_address'] = ip_address
        
        # Update user's last login
        user = User.query.get(user_id)
        user.last_login = now
        user.last_ip = ip_address
        user.failed_login_attempts = 0
        db.session.commit()
        
        app.logger.info(f"Session created for user {user_id} from IP {ip_address}")
        return session_id
    
    @staticmethod
    def validate_session() -> bool:
        """Validate current session"""
        # Check if session exists in Flask
        session_id = session.get('session_id')
        user_id = session.get('user_id')
        
        if not session_id or not user_id:
            return False
        
        # Check Redis cache first (faster)
        cached_session = redis_client.hgetall(f"session:{session_id}")
        if cached_session:
            # Verify user ID matches
            if int(cached_session.get('user_id', 0)) != user_id:
                return False
            
            # Check expiration
            expires_at = datetime.fromisoformat(cached_session['expires_at'])
            if datetime.utcnow() > expires_at:
                SessionManager.destroy_session(session_id)
                return False
            
            # Verify IP hasn't changed (optional, can be strict)
            if cached_session.get('ip_address') != request.remote_addr:
                app.logger.warning(f"IP mismatch for session {session_id}")
                # Could be a legitimate change (mobile switching networks)
                # Option to invalidate session or log warning
            
            # Update last activity
            redis_client.hset(f"session:{session_id}", 'last_activity', datetime.utcnow().isoformat())
            redis_client.expire(f"session:{session_id}", app.config['SESSION_IDLE_TIMEOUT'])
            
            return True
        
        # Fallback to database check
        session_record = SessionRecord.query.filter_by(
            session_id=session_id,
            user_id=user_id,
            is_active=True
        ).first()
        
        if session_record and not session_record.is_expired():
            # Update last activity
            session_record.last_activity = datetime.utcnow()
            db.session.commit()
            
            # Repopulate Redis cache
            session_data = {
                'user_id': user_id,
                'session_id': session_id,
                'ip_address': session_record.ip_address,
                'expires_at': session_record.expires_at.isoformat()
            }
            redis_client.hset(f"session:{session_id}", mapping=session_data)
            redis_client.expire(f"session:{session_id}", app.config['SESSION_IDLE_TIMEOUT'])
            
            return True
        
        # Session invalid - clear it
        SessionManager.destroy_session(session_id)
        return False
    
    @staticmethod
    def destroy_session(session_id: str = None):
        """Destroy a user session"""
        if not session_id:
            session_id = session.get('session_id')
        
        if session_id:
            # Remove from database
            session_record = SessionRecord.query.filter_by(
                session_id=session_id
            ).first()
            
            if session_record:
                session_record.is_active = False
                db.session.commit()
            
            # Remove from Redis
            redis_client.delete(f"session:{session_id}")
        
        # Clear Flask session
        session.clear()
    
    @staticmethod
    def destroy_all_user_sessions(user_id: int):
        """Destroy all sessions for a user (e.g., on password change)"""
        sessions = SessionRecord.query.filter_by(
            user_id=user_id,
            is_active=True
        ).all()
        
        for session_record in sessions:
            session_record.is_active = False
            redis_client.delete(f"session:{session_record.session_id}")
        
        db.session.commit()
    
    @staticmethod
    def _get_device_info() -> str:
        """Get device fingerprint information"""
        user_agent = request.headers.get('User-Agent', '')
        accept_lang = request.headers.get('Accept-Language', '')
        
        # Create a simple device fingerprint
        fingerprint = hashlib.sha256(
            f"{user_agent}:{accept_lang}".encode()
        ).hexdigest()[:16]
        
        return fingerprint

# ============================================================================
# Decorators
# ============================================================================

def login_required(f):
    """Decorator to require valid session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SessionManager.validate_session():
            session.clear()
            
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'Please login to access this resource'
                }), 401
            
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        # Add user to g for access in views
        user_id = session.get('user_id')
        g.current_user = User.query.get(user_id)
        
        return f(*args, **kwargs)
    
    return decorated_function

def role_required(*roles):
    """Decorator to require specific user role"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if g.current_user.role not in roles:
                app.logger.warning(
                    f"User {g.current_user.id} attempted to access restricted resource"
                )
                
                if request.is_json:
                    return jsonify({
                        'error': 'Forbidden',
                        'message': 'You do not have permission to access this resource'
                    }), 403
                
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# ============================================================================
# Routes
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """User login endpoint"""
    if request.method == 'GET':
        return render_template('login.html')
    
    try:
        data = request.get_json() if request.is_json else request.form
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        remember_me = data.get('remember_me', False)
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        # Use constant-time comparison for user existence check
        if not user:
            # Simulate password check to prevent timing attacks
            generate_password_hash('dummy_password')
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining = (user.locked_until - datetime.utcnow()).seconds // 60
            return jsonify({
                'error': f'Account locked. Try again in {remaining} minutes'
            }), 423  # Locked status
        
        # Verify password
        if not user.check_password(password):
            # Increment failed attempts
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                app.logger.warning(f"Account locked for user {user.id}")
            
            db.session.commit()
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Check if account is active
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 403
        
        # Create session
        SessionManager.create_session(user.id, remember_me)
        
        app.logger.info(f"User {user.id} logged in successfully")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': user.to_dict(),
            'redirect': url_for('dashboard')
        }), 200
        
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'An error occurred during login'}), 500

@app.route('/register', methods=['POST'])
@limiter.limit("3 per hour")
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].strip().lower()
        password = data['password']
        name = data['name'].strip()
        
        # Validate email format
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password strength
        if len(password) < 12:
            return jsonify({'error': 'Password must be at least 12 characters'}), 400
        
        if not re.search(r'[A-Z]', password):
            return jsonify({'error': 'Password must contain an uppercase letter'}), 400
        
        if not re.search(r'[a-z]', password):
            return jsonify({'error': 'Password must contain a lowercase letter'}), 400
        
        if not re.search(r'\d', password):
            return jsonify({'error': 'Password must contain a number'}), 400
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return jsonify({'error': 'Password must contain a special character'}), 400
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create new user
        user = User(
            email=email,
            name=name
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        app.logger.info(f"New user registered: {user.id}")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    """Protected dashboard route"""
    return jsonify({
        'message': f'Welcome {g.current_user.name}!',
        'user': g.current_user.to_dict()
    })

@app.route('/admin')
@role_required('admin')
def admin_panel():
    """Admin-only route"""
    return jsonify({
        'message': 'Admin panel',
        'user': g.current_user.to_dict()
    })

@app.route('/api/user/profile', methods=['GET', 'PUT'])
@login_required
def user_profile():
    """User profile endpoint"""
    if request.method == 'GET':
        return jsonify({
            'user': g.current_user.to_dict()
        })
    
    # Update profile
    try:
        data = request.get_json()
        user = g.current_user
        
        if 'name' in data:
            user.name = data['name'].strip()
        
        if 'email' in data:
            # Email change should require verification
            new_email = data['email'].strip().lower()
            if new_email != user.email:
                if User.query.filter_by(email=new_email).first():
                    return jsonify({'error': 'Email already in use'}), 409
                user.email = new_email
                user.email_verified = False
                # Send verification email here
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Profile update error: {str(e)}")
        return jsonify({'error': 'Profile update failed'}), 500

@app.route('/logout')
@login_required
def logout():
    """Logout endpoint"""
    session_id = session.get('session_id')
    SessionManager.destroy_session(session_id)
    
    app.logger.info(f"User {g.current_user.id} logged out")
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/api/sessions', methods=['GET'])
@login_required
def list_sessions():
    """List active sessions for current user"""
    sessions = SessionRecord.query.filter_by(
        user_id=g.current_user.id,
        is_active=True
    ).all()
    
    current_session_id = session.get('session_id')
    
    sessions_data = []
    for s in sessions:
        sessions_data.append({
            'id': s.id,
            'ip_address': s.ip_address,
            'user_agent': s.user_agent,
            'created_at': s.created_at.isoformat(),
            'last_activity': s.last_activity.isoformat(),
            'is_current': s.session_id == current_session_id,
            'device_info': s.device_info
        })
    
    return jsonify({'sessions': sessions_data})

@app.route('/api/sessions/<int:session_id>/revoke', methods=['POST'])
@login_required
def revoke_session(session_id):
    """Revoke a specific session"""
    session_record = SessionRecord.query.get_or_404(session_id)
    
    # Ensure user can only revoke their own sessions
    if session_record.user_id != g.current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Don't allow revoking current session through this endpoint
    if session_record.session_id == session.get('session_id'):
        return jsonify({'error': 'Use logout to end current session'}), 400
    
    session_record.is_active = False
    redis_client.delete(f"session:{session_record.session_id}")
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Session revoked'})

# ============================================================================
# Security Headers Middleware
# ============================================================================

@app.after_request
def add_security_headers(response):
    """Add additional security headers to every response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Remove server information
    response.headers['Server'] = ''
    
    return response

@app.before_request
def before_request():
    """Actions before each request"""
    # Ensure secure connection (when behind proxy, check X-Forwarded-Proto)
    if not request.is_secure and not app.debug:
        if request.headers.get('X-Forwarded-Proto', 'http') == 'http':
            # Redirect to HTTPS
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
    
    # Session validation on protected routes
    if request.endpoint and request.endpoint not in ['login', 'register', 'static']:
        if 'session_id' in session:
            if not SessionManager.validate_session():
                session.clear()
                return jsonify({'error': 'Session expired'}), 401

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_error(error):
    return jsonify({
        'error': 'Too many requests',
        'retry_after': error.description
    }), 429

# ============================================================================
# Application Initialization
# ============================================================================

def init_db():
    """Initialize database and create tables"""
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                email='admin@example.com',
                name='Admin',
                role='admin',
                email_verified=True
            )
            admin.set_password(os.environ.get('ADMIN_PASSWORD', 'ChangeMe123!@#'))
            db.session.add(admin)
            db.session.commit()
            app.logger.info('Default admin user created')

if __name__ == '__main__':
    init_db()
    # Never use debug=True in production
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=False,
        ssl_context='adhoc'  # Use proper SSL certificate in production
    )