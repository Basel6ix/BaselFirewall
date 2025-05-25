import json
import bcrypt
import os
import threading
import datetime
import time
from collections import defaultdict
from firewall.ids_ips import record_failed_login

USERS_FILE = os.path.join(os.path.dirname(__file__), '..', 'config', 'users.json')
LOGIN_LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'login_attempts.log')
_USERS_LOCK = threading.Lock()
_LOGIN_ATTEMPTS_LOCK = threading.Lock()

# Rate limiting settings
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW = 300  # 5 minutes
login_attempts = defaultdict(list)

def _cleanup_old_attempts():
    """Remove login attempts older than the window"""
    current_time = time.time()
    with _LOGIN_ATTEMPTS_LOCK:
        for ip in list(login_attempts.keys()):
            login_attempts[ip] = [attempt for attempt in login_attempts[ip]
                                if current_time - attempt < LOGIN_ATTEMPT_WINDOW]
            if not login_attempts[ip]:
                del login_attempts[ip]

def is_rate_limited(ip):
    """Check if an IP is currently rate limited"""
    _cleanup_old_attempts()
    with _LOGIN_ATTEMPTS_LOCK:
        return len(login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS

def record_login_attempt(ip, success):
    """Record a login attempt"""
    with _LOGIN_ATTEMPTS_LOCK:
        if not success:
            login_attempts[ip].append(time.time())
            if len(login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS:
                record_failed_login(ip)

def load_users():
    """Load users from the JSON file"""
    with _USERS_LOCK:
        if not os.path.exists(USERS_FILE):
            return {}
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_users(users):
    """Save users to the JSON file"""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with _USERS_LOCK:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify a password against its hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def authenticate(username, password, ip='127.0.0.1'):
    """Authenticate a user"""
    if is_rate_limited(ip):
        log_login_attempt(username, False, ip, "Rate limited")
        return None

    users = load_users()
    user = users.get(username)
    
    if user and verify_password(password, user.get('password', '')):
        log_login_attempt(username, True, ip)
        record_login_attempt(ip, True)
        return {
            'username': username,
            'role': user.get('role', 'user')
        }
    else:
        log_login_attempt(username, False, ip)
        record_login_attempt(ip, False)
        return None

def register_user(username, password, role='user', admin_username=None):
    """Register a new user (admin required for non-user roles)"""
    if not username or not password:
        return False, "Username and password are required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    users = load_users()
    if username in users:
        return False, "Username already exists"
    
    # Only admins can create admin users
    if role != 'user' and (not admin_username or not is_admin(admin_username)):
        return False, "Admin privileges required to create non-user roles"
    
    users[username] = {
        'password': hash_password(password),
        'role': role,
        'created_at': datetime.datetime.now().isoformat(),
        'created_by': admin_username if admin_username else 'self-registration'
    }
    save_users(users)
    return True, "User registered successfully"

def add_user(username, password, role='user'):
    """Add a new user"""
    if not username or not password:
        return False
    
    if len(password) < 8:
        return False
    
    users = load_users()
    if username in users:
        return False
    
    users[username] = {
        'password': hash_password(password),
        'role': role
    }
    save_users(users)
    return True

def change_password(username, old_password, new_password):
    """Change a user's password"""
    if len(new_password) < 8:
        return False, "New password must be at least 8 characters long"
    
    users = load_users()
    user = users.get(username)
    if not user:
        return False, "User not found"
    
    if not verify_password(old_password, user.get('password', '')):
        return False, "Old password incorrect"
    
    user['password'] = hash_password(new_password)
    user['password_updated_at'] = datetime.datetime.now().isoformat()
    save_users(users)
    return True, "Password changed successfully"

def is_admin(username):
    """Check if a user is an admin"""
    users = load_users()
    user = users.get(username)
    return user and user.get('role') == 'admin'

def reset_password(username, new_password, admin_username=None):
    """Reset a user's password (admin only)"""
    if not admin_username or not is_admin(admin_username):
        return False, "Admin privileges required"
    
    if len(new_password) < 8:
        return False, "New password must be at least 8 characters long"
    
    users = load_users()
    if username not in users:
        return False, "User not found"
    
    users[username]["password"] = hash_password(new_password)
    users[username]["password_reset_at"] = datetime.datetime.now().isoformat()
    users[username]["reset_by"] = admin_username
    save_users(users)
    return True, "Password reset successfully"

def remove_user(username, admin_username=None):
    """Remove a user"""
    users = load_users()
    if username not in users:
        return False
    
    if username == "admin":
        return False
    
    del users[username]
    save_users(users)
    return True

def list_users(admin_username=None):
    """List all users"""
    users = load_users()
    return [{'username': username, 'role': data['role']} for username, data in users.items()]

def log_login_attempt(username, success, ip='127.0.0.1', reason=None):
    """Log a login attempt"""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = 'SUCCESS' if success else 'FAILURE'
    reason_str = f" ({reason})" if reason else ""
    log_entry = f"[{timestamp}] LOGIN {status}: {username} from {ip}{reason_str}\n"
    
    os.makedirs(os.path.dirname(LOGIN_LOG_FILE), exist_ok=True)
    with open(LOGIN_LOG_FILE, 'a') as f:
        f.write(log_entry)
