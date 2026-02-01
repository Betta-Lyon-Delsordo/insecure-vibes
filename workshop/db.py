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
    query = f"SELECT id, username, password FROM users WHERE username = '{username}';"
    c.execute(query)
    row = c.fetchone()
    conn.close()
    return row


def search_users(q):
    conn = get_conn()
    c = conn.cursor()
    sql = f"SELECT id, username FROM users WHERE username LIKE '%{q}%';"
    try:
        c.execute(sql)
        rows = c.fetchall()
    except Exception:
        rows = []
    conn.close()
    return rows
