import os
import threading
from flask import Flask, jsonify, request, render_template, Response, send_from_directory, g, abort
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.orm.exc import NoResultFound
import time
import requests
import pefile
import magic
from tika import parser
from langdetect import detect
import logging
from MyLogger import Logger

# Create a logger instance
log = Logger(log_name='mserver', log_level=logging.DEBUG).get_logger()

# Database setup
DATABASE_URI = 'sqlite:///instance/files.db'
Base = declarative_base()
engine = create_engine(DATABASE_URI)
SessionLocal = scoped_session(sessionmaker(bind=engine))

# Define the FileMetadata model
class FileMetadata(Base):
    __tablename__ = 'file_metadata'
    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(String, unique=True, nullable=False)
    size = Column(Integer, nullable=False)
    modification_date = Column(Float, nullable=False)
    category = Column(String, nullable=True)
    inferred_category = Column(String, nullable=True)
    keywords = Column(String, nullable=True)
    summary = Column(String, nullable=True)
    content = Column(String, nullable=False)
    file_type = Column(String, nullable=True)
    creator_software = Column(String, nullable=True)
    origin_date = Column(String, nullable=True)
    pe_info = Column(String, nullable=True)  # New field for PE info

# Ensure database tables are created
Base.metadata.create_all(engine)

# Define the DirectoryMetadata model
class DirectoryMetadata(Base):
    __tablename__ = 'directory_metadata'
    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(String, unique=True, nullable=False)
    file_count = Column(Integer, nullable=False)
    total_size = Column(Integer, nullable=False)
    modification_date = Column(Float, nullable=False)

# Ensure database tables are created
Base.metadata.create_all(engine)

# Initialize Flask app
app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

@app.teardown_appcontext
def remove_session(exception=None):
    SessionLocal.remove()

# Initialize a queue for files to be scanned
scan_queue = []

# Lock for thread safety
queue_lock = threading.Lock()

# Function to process the scan queue
def process_scan_queue():
    while True:
        with queue_lock:
            if scan_queue:
                file_path = scan_queue.pop(0)
                log.info(f"Queue processing: {file_path}")
                scan_and_update_file(file_path)
        time.sleep(1)  # Adjust the sleep time as needed

# Start a background thread to process the queue
scan_thread = threading.Thread(target=process_scan_queue)
scan_thread.daemon = True
scan_thread.start()

# Function to extract text using Tika server
def extract_text_with_tika(file_path):
    with open(file_path, 'rb') as file:
        response = requests.put('http://localhost:9998/tika', files={'file': file})
        if response.status_code == 200:
            return response.text
        else:
            return ""

# Function to extract metadata from the file path
def infer_metadata_from_path(file_path):
    parts = file_path.split(os.sep)
    category = parts[-2] if len(parts) > 1 else 'Unknown'
    return category

# Function to use python-magic for file type detection
def detect_file_type(file_path):
    file_magic = magic.Magic(mime=True)
    mime_type = file_magic.from_file(file_path)
    file_type = mime_type.split('/')[0]
    creator_software = mime_type.split('/')[1] if len(mime_type.split('/')) > 1 else 'Unknown'
    return mime_type, file_type, creator_software

# Function to get PE file info
def get_pe_info(file_path):
    try:
        pe = pefile.PE(file_path)
        pe_info = {
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "number_of_sections": pe.FILE_HEADER.NumberOfSections
        }
        return str(pe_info)
    except Exception as e:
        return str(e)

# Function to scan and update a single file
def scan_and_update_file(file_path):
    session = SessionLocal()
    content = ""
    inferred_category = None
    keywords = None
    summary = None
    origin_date = str(os.path.getmtime(file_path))

    mime_type, file_type, creator_software = detect_file_type(file_path)
    size = os.path.getsize(file_path)
    modification_date = os.path.getmtime(file_path)
    category = infer_metadata_from_path(file_path)
    pe_info = ""

    if file_type == 'image':
        inferred_category = 'Image'
    elif file_path.lower().endswith('.exe'):
        content = get_pe_info(file_path)
        inferred_category = 'Executable'
        pe_info = content
    elif file_path.lower().endswith('.pdf') or file_path.lower().endswith('.docx'):
        parsed = parser.from_file(file_path)
        content = parsed.get('content', '') if parsed else ''
        source_lang = detect(content) if content else 'unknown'

        payload = {
            'file_path': file_path,
            'content': content[:500],
            'language': source_lang
        }

        response = requests.post('http://localhost:5001/infer', json=payload)
        if response.status_code == 200:
            data = response.json()
            inferred_category = data.get('category')
            keywords = data.get('keywords')
            summary = data.get('summary')

            if file_path.lower().endswith('.pdf') or file_path.lower().endswith('.docx'):
                content = summary
        else:
            log.info(f"Error processing file {file_path}: {response.text}")
    else:
        content = extract_text_with_tika(file_path)

    metadata = FileMetadata(
        path=file_path,
        size=size,
        modification_date=modification_date,
        category=category,
        inferred_category=inferred_category,
        keywords=keywords,
        summary=summary,
        content=content,
        file_type=file_type,
        creator_software=creator_software,
        origin_date=origin_date,
        pe_info=pe_info
    )
    session.add(metadata)
    session.commit()
    session.close()

@app.before_request
def before_request():
    # Example of setting variables to be accessed later
    g.endpoint = request.endpoint
    g.full_path = request.full_path

@app.errorhandler(404)
def page_not_found(e):
    # Access the stored endpoint
    endpoint = getattr(g, 'endpoint', 'Unknown')
    full_path = getattr(g, 'full_path', 'Unknown')
    log_message = (
        f"404 error at {request.url} - IP: {request.remote_addr} - "
        f"\nEndpoint: {endpoint}"
        f"\nfull_path: {full_path}"
    )
    app.logger.info(log_message)
    return "<h2>Page not found</h2>", 404

@app.route('/files', methods=['GET'])
def list_files():
    session = SessionLocal()
    relative_directory = request.args.get('directory', '/')
    directory = os.path.join(BASE_DIR, relative_directory.lstrip('/'))
    files = []
    file_list = os.scandir(directory)
    for entry in file_list:
        if entry.name.startswith('.'):
            continue
        file_path = os.path.join(directory, entry.name)
        relative_path = os.path.relpath(file_path, BASE_DIR)

        # Check if metadata exists in the database
        metadata = None
        try:
            if entry.is_dir():
                metadata = session.query(DirectoryMetadata).filter_by(path=file_path).one()
            else:
                metadata = session.query(FileMetadata).filter_by(path=file_path).one()
        except NoResultFound:
            pass
        files.append({
            'path': relative_path,
            'is_directory': entry.is_dir(),
            'id': entry.name if entry.is_file() else None,
            'metadata': {
                'id': getattr(metadata, 'id', None),
                'path': getattr(metadata, 'path', relative_path),
                'size': getattr(metadata, 'size', 0) if not entry.is_dir() else getattr(metadata, 'total_size', 0),
                'modification_date': getattr(metadata, 'modification_date', None),
                'category': getattr(metadata, 'category', None),
                'inferred_category': getattr(metadata, 'inferred_category', None),
                'keywords': getattr(metadata, 'keywords', None),
                'summary': getattr(metadata, 'summary', None),
                'file_type': getattr(metadata, 'file_type', None),
                'creator_software': getattr(metadata, 'creator_software', None),
                'origin_date': getattr(metadata, 'origin_date', None),
                'pe_info': getattr(metadata, 'pe_info', None) if not entry.is_dir() else None,
                'file_count': getattr(metadata, 'file_count', None) if entry.is_dir() else None
            }
        })

    # Sort folders first, then files, both alphabetically
    files.sort(key=lambda x: (not x['is_directory'], x['path'].lower()))
    response = jsonify(files)
    session.close()
    return response

# Endpoint to get file details and content
@app.route('/files/<path:file_id>', methods=['GET'])
def get_file(file_id):
    session = SessionLocal()
    file_path = os.path.join(BASE_DIR, file_id.lstrip('/'))
    file = session.query(FileMetadata).filter_by(path=file_path).first()

    if file:
        metadata = {
            'id': file.id,
            'path': file.path,
            'size': file.size,
            'modification_date': file.modification_date,
            'category': file.category,
            'inferred_category': file.inferred_category,
            'keywords': file.keywords,
            'summary': file.summary,
            'file_type': file.file_type,
            'creator_software': file.creator_software,
            'origin_date': file.origin_date,
            'pe_info': file.pe_info,
            'file_count': 0  # Not applicable for files
        }
        response = jsonify({'metadata': metadata, 'content': file.content})
        session.close()
        return response
    else:
        with queue_lock:
            scan_queue.append(file_path)
        log.info(f"/files/ not found: {file_path}")
        session.close()
        return jsonify({'error': 'File not found'}), 404

# Route to serve the HTML file
@app.route('/')
def serve_html():
    return send_from_directory(app.static_folder, 'index.html')

# Route for translation (not implemented )
@app.route('/translate', methods=['POST'])
def translate():
    data = request.json
    text = data.get('text')
    target_lang = data.get('target_lang', 'ja')
    translated_text = f"Translated to {target_lang}: {text}"
    return jsonify({'translated_text': translated_text})

@app.route('/thumbnails/<path:filename>')
def serve_thumbnail(filename):
    # Remove specific prefix from the filename if necessary
    prefix = 'win95/mcrlnsalg/'
    if filename.startswith(prefix):
        filename = filename[len(prefix):]

    log.debug(f"Processed filename after prefix removal: {filename}")

    base_name, ext = os.path.splitext(filename)
    webp_thumbnail = base_name + '.webp'
    png_thumbnail = base_name + '.png'
    jpg_thumbnail = base_name + '.jpg'

    webp_path = os.path.join(THUMBNAILS_DIR, webp_thumbnail)
    png_path = os.path.join(THUMBNAILS_DIR, png_thumbnail)
    jpg_path = os.path.join(THUMBNAILS_DIR, jpg_thumbnail)

    log.debug(f"WebP path: {webp_path}")
    log.debug(f"PNG path: {png_path}")
    log.debug(f"JPG path: {jpg_path}")

    file_path = webp_path
    if os.path.exists(file_path):
        log.debug(f"Serving WebP thumbnail: {file_path}")
        return send_thumbnail_with_correct_header(file_path, 'image/webp')
    elif os.path.exists(png_path):
        file_path = png_path
        log.debug(f"Serving PNG thumbnail: {file_path}")
        return send_thumbnail_with_correct_header(file_path, 'image/png')
    elif os.path.exists(jpg_path):
        file_path = jpg_path
        log.debug(f"Serving JPG thumbnail: {file_path}")
        return send_thumbnail_with_correct_header(file_path, 'image/jpeg')
    else:
        log.debug(f"Thumbnail not found for: {file_path}")
        abort(404)  # Thumbnail not found

def send_thumbnail_with_correct_header(file_path, mimetype):
    try:
        return send_from_directory(os.path.dirname(file_path), os.path.basename(file_path), mimetype=mimetype)
    except FileNotFoundError:
        log.error(f"File not found: {file_path}")
        abort(404, description="File not found")
    except Exception as e:
        log.error(f"Error sending file: {file_path}, error: {str(e)}")
        abort(500, description="Internal Server Error")

@app.route('/doc_preview/<path:filename>')
def preview(filename):
    if filename.endswith('.pdf'):
        return render_template('pdf_preview.html', file_url=f"/preview/{filename}")
    elif filename.endswith('.docx') or filename.lower().endswith('.doc'):
        return render_template('doc_preview.html', file_url=f"/preview/{filename}")
    elif filename.endswith('.xlsx') or filename.lower().endswith('.xls'):
        return render_template('excel_preview.html', file_url=f"/preview/{filename}")
    elif filename.lower().endswith('.csv'):
        return render_template('csv_preview.html', file_url=f"/preview/{filename}")
    else:
        return "File type not supported", 400

@app.route('/preview/<path:file_path>', methods=['GET', 'HEAD'])
def preview_file(file_path):
    file_dir, file_name = os.path.split(file_path)
    file_dir = "/" + file_dir
    log.debug(f"Preview:{file_dir}:{file_name}")
    if os.path.exists(f"{BASE_DIR}{file_dir}/{file_name}"):
        return send_from_directory(BASE_DIR + file_dir, file_name)
    else:
        log.error(f"Error file not found: {file_dir}/{file_name}")
        abort(404, description="File not found")

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(STATIC_DIR, filename)

# Configuration directories
BASE_DIR = os.environ.get('BASE_DIR', '/win95/mcrlnsalg')
STATIC_DIR = os.environ.get('STATIC_DIR', '/var/server/data/meta-server/static')
THUMBNAILS_DIR = os.environ.get('THUMBNAILS_DIR', '/var/server/data/meta-server/thumbnails')

if __name__ == '__main__':
    WEB_IP = os.environ.get('WEB_IP', '0.0.0.0')
    WEB_PORT = int(os.environ.get('WEB_PORT', '5000'))
    log.debug(f"port={WEB_PORT}, host={WEB_IP}, debug=True, use_reloader=False")
    app.run(port=WEB_PORT, host=WEB_IP, debug=True, use_reloader=False)
