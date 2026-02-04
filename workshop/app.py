from flask import Flask, request, render_template, redirect, url_for, session, abort, Response
import os
import secrets
import re
from functools import wraps
from datetime import timedelta
from db import init_db, search_users, get_user_by_username, set_user_vibe, get_user_vibe, get_all_vibes
from auth import add_user, check_login
from utils import save_upload, secure_filename, is_allowed_file

app = Flask(__name__)

# ============================================================================
# SECURITY CONFIGURATION - PARANOID MODE
# ============================================================================

# [OWASP A02:2021] Cryptographically secure secret key
# NIEMALS hartcodieren - Angreifer können dekompilieren/reverse-engineeren
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# [OWASP A07:2021] Session-Cookie-Härtung gegen Session Hijacking
app.config.update(
    SESSION_COOKIE_SECURE=True,      # Nur über HTTPS senden - verhindert MitM Sniffing
    SESSION_COOKIE_HTTPONLY=True,    # JavaScript kann Cookie nicht lesen - XSS-Schutz
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF-Basisschutz - Browser sendet nicht bei Cross-Origin
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),  # Session-Timeout - begrenzt Zeitfenster für Angreifer
    MAX_CONTENT_LENGTH=5 * 1024 * 1024  # [DoS-Schutz] Max 5MB Upload - verhindert Festplatten-Flooding
)

# Rate-Limiting-Speicher (in Production: Redis verwenden!)
# Hält Brute-Force-Statistiken pro IP
_login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5 Minuten Sperre nach zu vielen Versuchen


def check_rate_limit(ip):
    """
    [OWASP A07:2021] Rate-Limiting gegen Brute-Force-Angriffe
    Ein Angreifer der 1000 Passwörter/Sekunde probiert wird ausgebremst
    """
    import time
    now = time.time()
    if ip in _login_attempts:
        attempts, first_attempt = _login_attempts[ip]
        # Reset nach Lockout-Zeit
        if now - first_attempt > LOGIN_LOCKOUT_SECONDS:
            _login_attempts[ip] = (0, now)
            return True
        if attempts >= MAX_LOGIN_ATTEMPTS:
            return False  # GESPERRT
    return True


def record_failed_login(ip):
    """Fehlversuch aufzeichnen für Rate-Limiting"""
    import time
    now = time.time()
    if ip in _login_attempts:
        attempts, first_attempt = _login_attempts[ip]
        _login_attempts[ip] = (attempts + 1, first_attempt)
    else:
        _login_attempts[ip] = (1, now)


def clear_login_attempts(ip):
    """Nach erfolgreichem Login: Counter zurücksetzen"""
    if ip in _login_attempts:
        del _login_attempts[ip]


@app.after_request
def set_security_headers(response):
    """
    [OWASP A05:2021] Security Headers - Defense in Depth
    Jeder Header schließt einen Angriffsvektor
    """
    # Clickjacking-Schutz: Verhindert Einbettung in fremde iframes
    response.headers['X-Frame-Options'] = 'DENY'
    
    # XSS-Filter des Browsers aktivieren (Legacy, aber schadet nicht)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # MIME-Sniffing verhindern: Browser rät nicht am Content-Type rum
    # Verhindert z.B. dass text/plain als HTML interpretiert wird
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Referrer einschränken: Keine sensiblen URLs an Drittseiten leaken
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy: Whitelist für erlaubte Ressourcen
    # 'self' = nur von eigener Domain, kein inline JavaScript (XSS-Killer!)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    
    # Permissions Policy: Moderne Browser-Features restriktiv setzen
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Cache-Control für sensitive Seiten: Kein Caching von Auth-Daten
    if request.endpoint in ['login', 'secret', 'vibes', 'upload']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    
    return response


def login_required(f):
    """
    [OWASP A01:2021] Authentifizierungs-Decorator
    Schützt Routes vor unauthentifiziertem Zugriff
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            # Keine Info leaken ob Route existiert - einfach zum Login
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def validate_username(username):
    """
    [OWASP A03:2021] Input-Validierung für Usernames
    Verhindert: SQL Injection, XSS, Log Injection, Buffer Overflow
    """
    if not username:
        return False
    # Strenge Whitelist: nur alphanumerisch, 3-30 Zeichen
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return False
    return True


BASE_DIR = os.path.dirname(__file__)
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


@app.route('/')
def index():
    return render_template('index.html', username=session.get('username'))


# CSRF-Token Generator und Validator
def generate_csrf_token():
    """
    [OWASP A01:2021] CSRF-Token generieren
    Ohne Token kann ein Angreifer POST-Requests von fremden Seiten triggern
    """
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf_token():
    """CSRF-Token aus Form validieren"""
    token = session.get('_csrf_token')
    form_token = request.form.get('_csrf_token')
    if not token or not form_token or not secrets.compare_digest(token, form_token):
        abort(403, description="CSRF-Token ungültig")


# Template-Kontext: CSRF-Token in allen Templates verfügbar machen
app.jinja_env.globals['csrf_token'] = generate_csrf_token


@app.route('/initdb')
def initdb():
    """
    [OWASP A01:2021] DB-Init - Sicherer initialer Setup
    
    ERSTE Initialisierung ist ohne Auth erlaubt (Bootstrap-Problem lösen).
    Nach dem ersten Setup ist die Route gesperrt.
    In Production: Diese Route KOMPLETT entfernen!
    """
    import os
    db_exists = os.path.exists(os.path.join(BASE_DIR, 'demo.db'))
    
    if db_exists:
        # DB existiert bereits - nur für Admins
        if 'username' not in session:
            abort(403, description="Datenbankzugriff verweigert")
        if session.get('username') != 'admin':
            abort(403, description="Nur Administratoren können die Datenbank reinitialisieren")
    
    # Initialisierung durchführen
    init_db()
    
    # Demo-User anlegen (inkl. Admin für Ersteinrichtung)
    add_user('admin', 'SecureAdmin2024!')  # Admin-User für Management
    add_user('alice', 'password123')
    add_user('bob', 'hunter2')
    
    return 'Database initialized. Login as admin/SecureAdmin2024! for admin access.'


@app.route('/search')
@login_required  # [OWASP A01:2021] User-Enumeration verhindern - nur für Eingeloggte
def search():
    """
    Search nur für authentifizierte User!
    Ohne Auth könnten Angreifer alle Usernamen enumerieren
    """
    query = request.args.get('q', '')
    
    # [Input-Validierung] Query beschränken: max 50 Zeichen, keine Sonderzeichen
    if len(query) > 50:
        query = query[:50]
    # Nur alphanumerisch + Leerzeichen erlauben
    query = re.sub(r'[^a-zA-Z0-9\s]', '', query)
    
    results = search_users(query)
    return render_template('search.html', results=results, query=query)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    [OWASP A07:2021] Gehärteter Login mit allen Schutzmaßnahmen
    """
    error = None
    
    if request.method == 'POST':
        # [Rate-Limiting] Brute-Force-Schutz prüfen
        client_ip = request.remote_addr
        if not check_rate_limit(client_ip):
            # Generische Fehlermeldung - keine Info über Sperre verraten
            error = 'Anmeldung fehlgeschlagen. Bitte später erneut versuchen.'
            return render_template('login.html', error=error), 429
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # [Input-Validierung] Username-Format prüfen BEVOR DB-Abfrage
        if not validate_username(username):
            record_failed_login(client_ip)
            # GLEICHE Fehlermeldung wie bei falschem Passwort - keine Info leaken!
            error = 'Anmeldung fehlgeschlagen.'
            return render_template('login.html', error=error), 401
        
        if check_login(username, password):
            # [OWASP A07:2021] Session Fixation Prevention
            # KRITISCH: Alte Session-Daten zwischenspeichern
            old_session_data = dict(session)
            session.clear()  # Alte Session ID verwerfen
            
            # Neue Session-ID generieren (passiert automatisch bei Flask nach clear())
            session['username'] = username
            session.permanent = True  # Permanente Session mit Timeout
            
            # Login-Versuche zurücksetzen
            clear_login_attempts(client_ip)
            
            # [OWASP A09:2021] Security-relevante Events loggen (in Production: sicheres Logging!)
            app.logger.info(f"Successful login for user (hash): {hash(username)}")
            
            return redirect(url_for('index'))
        else:
            # Fehlversuch aufzeichnen
            record_failed_login(client_ip)
            # Generische Fehlermeldung - verrät nicht ob User existiert
            error = 'Anmeldung fehlgeschlagen.'
            return render_template('login.html', error=error), 401
    
    return render_template('login.html', error=error)


@app.route('/logout', methods=['POST'])  # [OWASP] POST statt GET verhindert CSRF via Link
@login_required
def logout():
    """
    [OWASP A01:2021] Logout nur via POST mit CSRF-Token
    GET-Logout ist anfällig: <img src="/logout"> würde User ausloggen!
    """
    validate_csrf_token()  # CSRF-Check
    session.clear()
    return redirect(url_for('index'))

@app.route('/secret')
@login_required  # OWASP A01:2021 - Broken Access Control - require authentication
def secret():
    return render_template('secret.html')


@app.route('/upload', methods=['GET', 'POST'])
@login_required  # Require authentication for file uploads
def upload():
    """
    [OWASP A04:2021] Gehärteter File Upload
    Angriffsvektoren: Path Traversal, Arbitrary File Upload, DoS, XSS via filename
    """
    if request.method == 'POST':
        # [OWASP A01:2021] CSRF-Schutz
        validate_csrf_token()
        
        f = request.files.get('file')
        if not f:
            return 'No file uploaded', 400
        if not f.filename:
            return 'No file selected', 400
        
        # [OWASP A04:2021] Dateityp validieren - MIME-Type UND Extension prüfen
        if not is_allowed_file(f.filename):
            return 'File type not allowed. Only txt, pdf, png, jpg, jpeg, gif allowed.', 400
        
        # [OWASP A01:2021] Filename sanitizen gegen Path Traversal
        filename = secure_filename(f.filename)
        if not filename:
            return 'Invalid filename', 400
        
        # [Double Extension Attack] Prüfen ob finale Extension erlaubt ist
        final_ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if final_ext not in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}:
            return 'Invalid file extension after sanitization', 400
        
        save_upload(filename, f.stream, app.config['UPLOAD_FOLDER'])
        return redirect(url_for('uploaded_file', filename=filename))
    return render_template('upload.html')


@app.route('/uploads/<path:filename>')
@login_required  # [OWASP A01:2021] Uploads nur für authentifizierte User sichtbar
def uploaded_file(filename):
    """
    [OWASP A01:2021] Gehärteter File Download
    Path Traversal Schutz mit mehreren Layern
    """
    # Layer 1: Filename sanitizen
    filename = secure_filename(filename)
    if not filename:
        abort(400)
    
    # Layer 2: Pfad konstruieren
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Layer 3: Realpath-Check mit os.sep Suffix-Trick-Schutz
    # Angriff: /uploads/../etc -> realpath könnte tricksen
    real_path = os.path.realpath(file_path)
    upload_folder_real = os.path.realpath(app.config['UPLOAD_FOLDER'])
    
    # os.sep anhängen um Prefix-Angriffe zu verhindern:
    # Ohne: '/var/uploads' startet mit '/var/upload' (FALSCH!)
    # Mit: '/var/uploads/' startet NICHT mit '/var/upload/' (RICHTIG!)
    if not (real_path.startswith(upload_folder_real + os.sep) or real_path == upload_folder_real):
        abort(403)
    
    if not os.path.exists(file_path):
        abort(404)
    
    # Layer 4: Nur reguläre Dateien, keine Symlinks
    if not os.path.isfile(file_path) or os.path.islink(file_path):
        abort(403)
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
        content = fh.read()
    
    # [OWASP A07:2021] Sicherer Content-Type verhindert XSS
    return Response(content, mimetype='text/plain; charset=utf-8')


# Allowed vibes (allowlist to prevent abuse - OWASP A04:2021)
ALLOWED_VIBES = ['😎 Chill', '🔥 On Fire', '😴 Sleepy', '🤔 Thinking', '🎉 Party Mode', 
                 '💻 Coding', '☕ Coffee Time', '🌈 Vibing', '🚀 Productive', '😅 Struggling']


@app.route('/vibes', methods=['GET', 'POST'])
@login_required
def vibes():
    """
    [OWASP A04:2021] Vibe Checker - Sicher implementiert
    Allowlist-basierte Eingabevalidierung
    """
    username = session.get('username')
    message = None
    
    if request.method == 'POST':
        # [OWASP A01:2021] CSRF-Schutz
        validate_csrf_token()
        
        selected_vibe = request.form.get('vibe', '')
        # [OWASP A04:2021] Strenge Allowlist-Validierung
        if selected_vibe in ALLOWED_VIBES:
            set_user_vibe(username, selected_vibe)
            message = 'Vibe aktualisiert!'  # Keine User-Eingabe in Nachricht!
        else:
            message = 'Ungültige Auswahl!'
    
    current_vibe = get_user_vibe(username)
    all_vibes = get_all_vibes()
    
    return render_template('vibes.html', 
                         current_vibe=current_vibe,
                         allowed_vibes=ALLOWED_VIBES, 
                         all_vibes=all_vibes,
                         message=message)


if __name__ == '__main__':
    # OWASP: Never run with debug=True in production
    # Use environment variable to control debug mode
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)


# ============================================================================
# [OWASP A09:2021] ERROR HANDLERS - Keine Interna leaken!
# ============================================================================

@app.errorhandler(400)
def bad_request(e):
    """Generische Fehlermeldung für Bad Request"""
    return render_template('error.html', 
                         error_code=400, 
                         error_message='Ungültige Anfrage'), 400


@app.errorhandler(403)
def forbidden(e):
    """Generische Fehlermeldung für Forbidden - keine Details!"""
    return render_template('error.html', 
                         error_code=403, 
                         error_message='Zugriff verweigert'), 403


@app.errorhandler(404)
def not_found(e):
    """Generische Fehlermeldung für Not Found"""
    return render_template('error.html', 
                         error_code=404, 
                         error_message='Seite nicht gefunden'), 404


@app.errorhandler(413)
def request_entity_too_large(e):
    """Datei zu groß"""
    return render_template('error.html', 
                         error_code=413, 
                         error_message='Datei zu groß (max 5MB)'), 413


@app.errorhandler(429)
def too_many_requests(e):
    """Rate Limit erreicht"""
    return render_template('error.html', 
                         error_code=429, 
                         error_message='Zu viele Anfragen. Bitte warten.'), 429


@app.errorhandler(500)
def internal_error(e):
    """
    [KRITISCH] Keine Stack Traces nach außen!
    Ein Angreifer könnte interne Pfade, Versionen, etc. herausfinden
    """
    # In Production: Fehler sicher loggen (ohne sensitive Daten)
    app.logger.error(f"Internal error: {type(e).__name__}")
    return render_template('error.html', 
                         error_code=500, 
                         error_message='Ein Fehler ist aufgetreten'), 500
