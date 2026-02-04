from db import add_user as db_add_user, get_user_by_username
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time


# Dummy-Hash für Timing-Attack-Schutz
# Wird berechnet wenn User nicht existiert, um gleiche Antwortzeit zu haben
_DUMMY_HASH = generate_password_hash("dummy_password_for_timing_protection")


def add_user(username, password):
    """
    [OWASP A02:2021] User mit sicher gehashtem Passwort anlegen
    Verwendet PBKDF2 mit hohem Iterationscount
    """
    # Hash mit Werkzeug's sicherem Hashing (PBKDF2-SHA256, 600k Iterationen)
    hashed_password = generate_password_hash(
        password,
        method='pbkdf2:sha256',
        salt_length=16
    )
    db_add_user(username, hashed_password)


def check_login(username, password):
    """
    [OWASP A07:2021] Timing-Attack-resistenter Login-Check
    
    PROBLEM: Wenn wir bei nicht-existentem User sofort False returnen,
    ist die Antwort schneller als bei existierendem User (wo wir hashen).
    -> Angreifer kann durch Zeitmessung Usernamen enumerieren!
    
    LÖSUNG: Bei nicht-existentem User trotzdem einen Passwort-Check
    gegen einen Dummy-Hash durchführen. Dauert gleich lang!
    """
    user = get_user_by_username(username)
    
    if not user:
        # [TIMING-ATTACK-SCHUTZ] Dummy-Vergleich durchführen
        # Dauert genauso lange wie echter Vergleich -> keine Info-Leak!
        check_password_hash(_DUMMY_HASH, password)
        return False
    
    stored_password_hash = user[2]
    
    # Werkzeug's check_password_hash verwendet bereits constant-time comparison
    return check_password_hash(stored_password_hash, password)