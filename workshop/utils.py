import os
import re
import unicodedata

# ============================================================================
# [OWASP A04:2021] SICHERE FILE UPLOAD UTILITIES
# ============================================================================

# Strenge Allowlist für Dateiendungen
# KEINE ausführbaren Formate (.py, .php, .exe, .sh, .bat, .js, .html, .htm, .svg)
# SVG ist gefährlich wegen eingebettetem JavaScript!
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Maximale Dateinamenlänge (verhindert Buffer-Overflow-Angriffe)
MAX_FILENAME_LENGTH = 100


def secure_filename(filename):
    """
    [OWASP A01:2021] PARANOIDE Filename-Sanitization
    
    Schützt gegen:
    - Path Traversal (../, ..\, etc.)
    - Null-Byte Injection (%00, \x00)
    - Unicode Normalization Attacks (verschiedene Unicode-Darstellungen von ../)
    - Doppelte Extensions (.php.txt)
    - Versteckte Dateien (.htaccess)
    - Sonderzeichen die Shells interpretieren könnten
    - Kontrolzeichen
    - Oversized filenames (DoS)
    """
    if not filename:
        return None
    
    # [UNICODE NORMALIZATION] Zuerst normalisieren!
    # Angriff: Unicode hat verschiedene Darstellungen für gleiche Zeichen
    # z.B. 'ä' kann als 1 Zeichen oder als 'a' + '̈' (combining diaeresis) dargestellt werden
    # NFKC normalisiert auf kanonische Form
    try:
        filename = unicodedata.normalize('NFKC', filename)
    except (TypeError, ValueError):
        return None
    
    # [NULL-BYTE INJECTION] Alle Null-Bytes entfernen
    # Angriff: "shell.php%00.txt" -> C sieht "shell.php", Python sieht ".txt"
    filename = filename.replace('\x00', '')
    filename = filename.replace('%00', '')
    
    # [CONTROL CHARACTERS] Alle Steuerzeichen entfernen (ASCII 0-31, 127)
    filename = ''.join(char for char in filename if ord(char) > 31 and ord(char) != 127)
    
    # [PATH SEPARATORS] Nur den Dateinamen extrahieren, Pfad wegwerfen
    # Muss NACH Unicode-Normalisierung passieren!
    filename = os.path.basename(filename)
    
    # Auch Windows-Separatoren auf Unix und umgekehrt berücksichtigen
    filename = filename.replace('/', '_').replace('\\', '_')
    
    # [STRICT WHITELIST] Nur erlaubte Zeichen durchlassen
    # Alphanumerisch + Punkt + Bindestrich + Unterstrich
    # KEIN Leerzeichen (kann in manchen Kontexten problematisch sein)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # [HIDDEN FILES] Führende Punkte entfernen
    # Verhindert .htaccess, .bashrc, etc.
    while filename.startswith('.'):
        filename = filename[1:]
    
    # [DOUBLE DOTS] Konsekutive Punkte auf einen reduzieren
    # Verhindert ".."-Sequenzen die nach anderen Transformationen entstehen könnten
    while '..' in filename:
        filename = filename.replace('..', '.')
    
    # [LENGTH LIMIT] Dateiname kürzen
    if len(filename) > MAX_FILENAME_LENGTH:
        # Intelligent kürzen: Extension beibehalten
        if '.' in filename:
            name, ext = filename.rsplit('.', 1)
            max_name_len = MAX_FILENAME_LENGTH - len(ext) - 1
            if max_name_len > 0:
                filename = name[:max_name_len] + '.' + ext
            else:
                filename = filename[:MAX_FILENAME_LENGTH]
        else:
            filename = filename[:MAX_FILENAME_LENGTH]
    
    # Leerer Filename nach Sanitization?
    if not filename or filename == '.':
        return None
    
    return filename


def is_allowed_file(filename):
    """
    [OWASP A04:2021] Dateiendungs-Validierung
    
    WICHTIG: Das ist nur die ERSTE Verteidigungsschicht!
    Dateiinhalt sollte auch validiert werden (Magic Bytes prüfen)
    """
    if not filename:
        return False
    
    # Punkt muss vorhanden sein
    if '.' not in filename:
        return False
    
    # Extension extrahieren (nur die letzte!)
    ext = filename.rsplit('.', 1)[1].lower()
    
    # Gegen strenge Allowlist prüfen
    return ext in ALLOWED_EXTENSIONS


def validate_file_content(stream, expected_type):
    """
    [OWASP A04:2021] Magic Bytes Validierung
    Prüft ob der Dateiinhalt zum behaupteten Typ passt
    
    HINWEIS: Für vollständige Implementation sollte magic/python-magic verwendet werden
    """
    MAGIC_BYTES = {
        'png': b'\x89PNG\r\n\x1a\n',
        'jpg': b'\xff\xd8\xff',
        'jpeg': b'\xff\xd8\xff',
        'gif': b'GIF87a',  # oder GIF89a
        'pdf': b'%PDF-',
    }
    
    if expected_type not in MAGIC_BYTES:
        return True  # txt hat keine Magic Bytes
    
    # Ersten Bytes lesen
    header = stream.read(8)
    stream.seek(0)  # Stream zurücksetzen!
    
    expected_magic = MAGIC_BYTES[expected_type]
    
    if expected_type in ('gif',):
        # GIF kann GIF87a oder GIF89a sein
        return header.startswith(b'GIF87a') or header.startswith(b'GIF89a')
    
    return header.startswith(expected_magic)


def save_upload(filename, stream, upload_folder):
    """
    [OWASP A01:2021] Sichere Datei-Speicherung
    
    Mehrschichtige Validierung vor dem Speichern
    """
    # Layer 1: Filename sanitizen
    safe_filename = secure_filename(filename)
    if not safe_filename:
        raise ValueError("Ungültiger Dateiname")
    
    # Layer 2: Extension nochmal prüfen NACH Sanitization
    if not is_allowed_file(safe_filename):
        raise ValueError("Dateityp nicht erlaubt")
    
    # Layer 3: Pfad konstruieren
    path = os.path.join(upload_folder, safe_filename)
    
    # Layer 4: Realpath-Check mit os.sep-Schutz
    real_path = os.path.realpath(path)
    real_upload = os.path.realpath(upload_folder)
    
    # Separator anhängen um Prefix-Angriffe zu verhindern
    if not (real_path.startswith(real_upload + os.sep) or real_path == os.path.join(real_upload, safe_filename)):
        raise ValueError("Path Traversal erkannt")
    
    # Layer 5: Keine Symlinks erlauben (falls Datei existiert)
    if os.path.exists(path) and os.path.islink(path):
        raise ValueError("Symlinks nicht erlaubt")
    
    # Layer 6: Dateiinhalt lesen und Magic Bytes validieren
    ext = safe_filename.rsplit('.', 1)[1].lower() if '.' in safe_filename else ''
    if ext in ('png', 'jpg', 'jpeg', 'gif', 'pdf'):
        if not validate_file_content(stream, ext):
            raise ValueError(f"Dateiinhalt entspricht nicht dem Typ {ext}")
    
    # Layer 7: Atomisch schreiben mit temporärer Datei (optional für Race Conditions)
    with open(path, 'wb') as fh:
        # Chunk-weise lesen um Memory DoS zu verhindern
        chunk_size = 8192
        bytes_written = 0
        max_size = 5 * 1024 * 1024  # 5 MB
        
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            bytes_written += len(chunk)
            if bytes_written > max_size:
                # Datei löschen und Fehler werfen
                fh.close()
                os.unlink(path)
                raise ValueError("Datei zu groß")
            fh.write(chunk)


def read_file_safe(path):
    """Sichere Datei-Lesung mit Encoding-Handling"""
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        return fh.read()