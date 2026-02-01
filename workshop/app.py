from flask import Flask, request, render_template, redirect, url_for, session, abort
import os
from db import init_db, search_users, get_user_by_username
from auth import add_user, check_login
from utils import save_upload

app = Flask(__name__)
app.secret_key = 'dev-secret-key'  # development secret key
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
# Secret page for more important info
def secret():
    return render_template('secret.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f:
            return 'No file uploaded', 400
        filename = f.filename
        save_upload(filename, f.stream, app.config['UPLOAD_FOLDER'])
        return redirect(url_for('uploaded_file', filename=filename))
    return render_template('upload.html')


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        abort(404)
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
        content = fh.read()
    return content


if __name__ == '__main__':
    app.run(debug=True)
