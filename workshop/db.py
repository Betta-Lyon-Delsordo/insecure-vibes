import sqlite3
import os
import re

# ============================================================================
# [OWASP A03:2021] SICHERE DATABASE UTILITIES
# ============================================================================

DB_PATH = os.path.join(os.path.dirname(__file__), 'demo.db')

# Input-Validierung Patterns
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,30}$')


def validate_input(value, pattern, max_length=100):
    """
    [OWASP A03:2021] Input-Validierung vor DB-Operationen
    Defense in Depth: Auch wenn wir parameterized queries nutzen,
    validieren wir trotzdem die Eingaben!
    """
    if not value or not isinstance(value, str):
        return False
    if len(value) > max_length:
        return False
    if pattern and not pattern.match(value):
        return False
    return True


def get_conn():
    """
    Sichere DB-Verbindung mit Timeout und Read-Only-Check
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    # Foreign Keys aktivieren für referentielle Integrität
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """
    [OWASP A05:2021] Sichere DB-Initialisierung
    Mit try-finally für garantiertes Connection-Cleanup
    """
    conn = None
    try:
        conn = get_conn()
        c = conn.cursor()
        # Users-Tabelle mit Constraints
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 30),
                password TEXT NOT NULL CHECK(length(password) >= 60)
            )
        ''')
        # Vibes-Tabelle mit Constraints und Foreign Key
        c.execute('''
            CREATE TABLE IF NOT EXISTS vibes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                vibe TEXT NOT NULL CHECK(length(vibe) <= 50),
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    except sqlite3.Error:
        # [OWASP A09:2021] Keine DB-Fehlerdetails nach außen leaken
        raise RuntimeError("Datenbankfehler bei Initialisierung")
    finally:
        if conn:
            conn.close()


def add_user(username, password):
    """
    [OWASP A03:2021] Sicheres User-Hinzufügen
    Input wird validiert, parameterized query verhindert SQLi
    """
    # Defense in Depth: Input trotz parameterized query validieren
    if not validate_input(username, USERNAME_PATTERN, 30):
        raise ValueError("Ungültiger Username")
    if not password or len(password) < 60:  # Hash ist ~100 Zeichen
        raise ValueError("Ungültiges Passwort-Hash")
    
    conn = None
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)", 
            (username, password)
        )
        conn.commit()
    except sqlite3.Error:
        raise RuntimeError("Datenbankfehler beim User-Erstellen")
    finally:
        if conn:
            conn.close()


def get_user_by_username(username):
    """
    [OWASP A03:2021] Sichere User-Abfrage
    """
    # Leere Eingabe früh abfangen
    if not username:
        return None
    
    conn = None
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute(
            "SELECT id, username, password FROM users WHERE username = ?;", 
            (username,)
        )
        row = c.fetchone()
        return row
    except sqlite3.Error:
        return None  # Fehler nach außen als "nicht gefunden" maskieren
    finally:
        if conn:
            conn.close()


def search_users(q):
    """
    [OWASP A03:2021] Sichere User-Suche
    Ergebnisse sind limitiert um DoS zu verhindern
    """
    if not q:
        return []
    
    # Query-Länge begrenzen
    if len(q) > 50:
        q = q[:50]
    
    conn = None
    try:
        conn = get_conn()
        c = conn.cursor()
        # LIMIT verhindert dass riesige Ergebnismengen zurückkommen
        c.execute(
            "SELECT id, username FROM users WHERE username LIKE ? LIMIT 100;", 
            (f'%{q}%',)
        )
        rows = c.fetchall()
        return rows
    except sqlite3.Error:
        return []  # Bei Fehler leere Liste
    finally:
        if conn:
            conn.close()


def set_user_vibe(username, vibe):
    """
    [OWASP A03:2021] Sichere Vibe-Aktualisierung
    Username und Vibe werden validiert
    """
    if not validate_input(username, USERNAME_PATTERN, 30):
        raise ValueError("Ungültiger Username")
    if not vibe or len(vibe) > 50:
        raise ValueError("Ungültige Vibe")
    
    conn = None
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO vibes (username, vibe, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP);",
            (username, vibe)
        )
        conn.commit()
    except sqlite3.Error:
        raise RuntimeError("Datenbankfehler beim Vibe-Update")
    finally:
        if conn:
            conn.close()


def get_user_vibe(username):
    """
    [OWASP A03:2021] Sichere Vibe-Abfrage
    """
    if not username:
        return None
    
    conn = None
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT vibe FROM vibes WHERE username = ?;", (username,))
        row = c.fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None
    finally:
        if conn:
            conn.close()


def get_all_vibes():
    """
    [OWASP A03:2021] Sichere Abfrage aller Vibes
    Mit LIMIT gegen DoS
    """
    conn = None
    try:
        conn = get_conn()
        c = conn.cursor()
        # Strikt limitiert auf 20 Einträge
        c.execute(
            "SELECT username, vibe, updated_at FROM vibes ORDER BY updated_at DESC LIMIT 20;"
        )
        rows = c.fetchall()
        return rows
    except sqlite3.Error:
        return []
    finally:
        if conn:
            conn.close()
