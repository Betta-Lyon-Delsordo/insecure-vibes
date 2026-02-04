import os
import re

# Allowed file extensions for upload (OWASP A04:2021 - Insecure Design)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def secure_filename(filename):
    """
    Sanitize filename to prevent path traversal attacks (OWASP A01:2021 - Broken Access Control).
    Removes directory separators, null bytes, and other dangerous characters.
    """
    if not filename:
        return None
    # Remove any null bytes
    filename = filename.replace('\x00', '')
    # Get just the filename, removing any directory path
    filename = os.path.basename(filename)
    # Remove any remaining path separators and dangerous characters
    # Keep only alphanumeric, dots, hyphens, and underscores
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    # Prevent hidden files and directory traversal
    filename = filename.lstrip('.')
    # Limit filename length
    if len(filename) > 255:
        filename = filename[:255]
    return filename if filename else None


def is_allowed_file(filename):
    """Check if the file extension is in the allowed list."""
    if not filename:
        return False
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(filename, stream, upload_folder):
    """Safely save uploaded file."""
    # Sanitize filename before saving
    safe_filename = secure_filename(filename)
    if not safe_filename:
        raise ValueError("Invalid filename")
    path = os.path.join(upload_folder, safe_filename)
    # Additional check: ensure the final path is within upload folder
    real_path = os.path.realpath(path)
    real_upload = os.path.realpath(upload_folder)
    if not real_path.startswith(real_upload):
        raise ValueError("Path traversal detected")
    with open(path, 'wb') as fh:
        fh.write(stream.read())


def read_file_safe(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        return fh.read()