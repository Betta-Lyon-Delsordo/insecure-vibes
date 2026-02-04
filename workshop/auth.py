from db import add_user as db_add_user, get_user_by_username
from werkzeug.security import generate_password_hash, check_password_hash


def add_user(username, password):
    """Add user with securely hashed password (OWASP A02:2021 - Cryptographic Failures)"""
    # Hash password using werkzeug's secure password hashing (uses pbkdf2 by default)
    hashed_password = generate_password_hash(password)
    db_add_user(username, hashed_password)


def check_login(username, password):
    """Verify login credentials against securely stored password hash"""
    user = get_user_by_username(username)
    if not user:
        return False
    stored_password_hash = user[2]
    # Use constant-time comparison to prevent timing attacks
    return check_password_hash(stored_password_hash, password)