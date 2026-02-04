from flask import Flask, request, render_template, redirect, url_for, session, abort, Response
import os
import secrets
from functools import wraps
from db import init_db, search_users, get_user_by_username, set_user_vibe, get_user_vibe, get_all_vibes
from auth import add_user, check_login
from utils import save_upload, secure_filename, is_allowed_file

app = Flask(__name__)
# Use cryptographically secure secret key (OWASP A02:2021 - Cryptographic Failures)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)


# Login required decorator for protected routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
BASE_DIR = os.path.dirname(__file__)
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


@app.route('/')
def index():
    return render_template('index.html', username=session.get('username'))


@app.route('/initdb')
def initdb():
    init_db()
    # add a couple of demo users
    add_user('alice', 'password123')
    add_user('bob', 'hunter2')
    return 'Database initialized with demo users.'


@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = search_users(query)
    return render_template('search.html', results=results, query=query)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if check_login(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return 'Login failed', 401
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/secret')
@login_required  # OWASP A01:2021 - Broken Access Control - require authentication
def secret():
    return render_template('secret.html')


@app.route('/upload', methods=['GET', 'POST'])
@login_required  # Require authentication for file uploads
def upload():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f:
            return 'No file uploaded', 400
        if not f.filename:
            return 'No file selected', 400
        # Validate file type (OWASP A04:2021 - Insecure Design)
        if not is_allowed_file(f.filename):
            return 'File type not allowed. Only txt, pdf, png, jpg, jpeg, gif allowed.', 400
        # Sanitize filename to prevent path traversal (OWASP A01:2021 - Broken Access Control)
        filename = secure_filename(f.filename)
        if not filename:
            return 'Invalid filename', 400
        save_upload(filename, f.stream, app.config['UPLOAD_FOLDER'])
        return redirect(url_for('uploaded_file', filename=filename))
    return render_template('upload.html')


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # Sanitize filename to prevent path traversal attacks
    filename = secure_filename(filename)
    if not filename:
        abort(400)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    # Verify the resolved path is within upload folder (path traversal protection)
    real_path = os.path.realpath(file_path)
    upload_folder_real = os.path.realpath(app.config['UPLOAD_FOLDER'])
    if not real_path.startswith(upload_folder_real):
        abort(403)
    if not os.path.exists(file_path):
        abort(404)
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
        content = fh.read()
    # Return with safe content type to prevent XSS
    return Response(content, mimetype='text/plain')


# Allowed vibes (allowlist to prevent abuse - OWASP A04:2021)
ALLOWED_VIBES = ['😎 Chill', '🔥 On Fire', '😴 Sleepy', '🤔 Thinking', '🎉 Party Mode', 
                 '💻 Coding', '☕ Coffee Time', '🌈 Vibing', '🚀 Productive', '😅 Struggling']


@app.route('/vibes', methods=['GET', 'POST'])
@login_required
def vibes():
    """Vibe Checker - Set and view your current vibe!"""
    username = session.get('username')
    message = None
    
    if request.method == 'POST':
        selected_vibe = request.form.get('vibe', '')
        # Validate vibe is in allowlist (OWASP A04:2021 - Insecure Design)
        if selected_vibe in ALLOWED_VIBES:
            set_user_vibe(username, selected_vibe)
            message = f'Vibe updated to: {selected_vibe}'
        else:
            message = 'Invalid vibe selected!'
    
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
