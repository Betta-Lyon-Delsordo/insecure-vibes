import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'demo.db')


def get_conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    # Vibes table for the Vibe Checker feature
    c.execute('''
        CREATE TABLE IF NOT EXISTS vibes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            vibe TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def add_user(username, password):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_conn()
    c = conn.cursor()
    # Use parameterized query to prevent SQL injection (OWASP A03:2021 - Injection)
    c.execute("SELECT id, username, password FROM users WHERE username = ?;", (username,))
    row = c.fetchone()
    conn.close()
    return row


def search_users(q):
    conn = get_conn()
    c = conn.cursor()
    # Use parameterized query to prevent SQL injection (OWASP A03:2021 - Injection)
    try:
        c.execute("SELECT id, username FROM users WHERE username LIKE ?;", (f'%{q}%',))
        rows = c.fetchall()
    except Exception:
        rows = []
    conn.close()
    return rows


def set_user_vibe(username, vibe):
    """Set a user's current vibe (securely with parameterized query)."""
    conn = get_conn()
    c = conn.cursor()
    # Use parameterized query to prevent SQL injection
    c.execute(
        "INSERT OR REPLACE INTO vibes (username, vibe, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP);",
        (username, vibe)
    )
    conn.commit()
    conn.close()


def get_user_vibe(username):
    """Get a user's current vibe (securely with parameterized query)."""
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT vibe FROM vibes WHERE username = ?;", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


def get_all_vibes():
    """Get all users' vibes for the vibe board."""
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT username, vibe, updated_at FROM vibes ORDER BY updated_at DESC LIMIT 20;")
    rows = c.fetchall()
    conn.close()
    return rows
