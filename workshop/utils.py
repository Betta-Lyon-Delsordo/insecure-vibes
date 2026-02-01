import os

def save_upload(filename, stream, upload_folder):
    path = os.path.join(upload_folder, filename)
    with open(path, 'wb') as fh:
        fh.write(stream.read())

def read_file_safe(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        return fh.read()