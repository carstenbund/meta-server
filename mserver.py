from flask import Flask, jsonify, send_from_directory
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float
from flask_cors import CORS
from tika import parser
import threading
import time
import os
import requests  # Used to communicate with the inference server

# Database setup
DATABASE_URI = 'sqlite:///files.db'
Base = declarative_base()
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

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
    pe_info = Column(String, nullable=True)

# Ensure database tables are created
Base.metadata.create_all(engine)

# Initialize Flask app
app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

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
                # Implement scanning logic here (similar to scan_directory function)
                scan_and_update_file(file_path)
        time.sleep(1)  # Adjust the sleep time as needed

# Start a background thread to process the queue
scan_thread = threading.Thread(target=process_scan_queue)
scan_thread.daemon = True
scan_thread.start()

# Function to scan and update a single file
def scan_and_update_file(file_path):
    session = Session()

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

    # Extract content based on file type
    content = ""
    if file_path.lower().endswith('.pdf'):
        content = extract_text_from_pdf(file_path)
    elif file_path.lower().endswith('.docx'):
        content = extract_text_from_docx(file_path)
    else:
        parsed = parser.from_file(file_path)
        content = parsed['content'] if parsed and 'content' in parsed else ''

    # Send content to inference server
    relative_path = os.path.relpath(file_path, start='/path/to/your/files')
    inference_response = requests.post('http://localhost:5001/infer', json={'file_path': relative_path})
    if inference_response.status_code == 200:
        inference_data = inference_response.json()
    else:
        inference_data = {
            'inferred_category': 'N/A',
            'keywords': 'N/A',
            'summary': 'N/A'
        }

    # Implement the scanning logic
    pe_info = get_pe_info(file_path) if file_path.lower().endswith('.exe') else ''
    metadata = FileMetadata(
        path=file_path,
        size=os.path.getsize(file_path),
        modification_date=os.path.getmtime(file_path),
        inferred_category=inference_data['inferred_category'],
        keywords=inference_data['keywords'],
        summary=inference_data['summary'],
        pe_info=pe_info
    )
    session.add(metadata)
    session.commit()
    session.close()

# Endpoint to list all files
@app.route('/files', methods=['GET'])
def list_files():
    files = session.query(FileMetadata).all()
    return jsonify([{
        'id': file.id,
        'path': file.path,
        'size': file.size,
        'modification_date': file.modification_date,
        'category': file.category,
        'inferred_category': file.inferred_category,
        'keywords': file.keywords,
        'summary': file.summary,
        'pe_info': file.pe_info
    } for file in files])

# Endpoint to get file details and content
@app.route('/files/<int:file_id>', methods=['GET'])
def get_file(file_id):
    file = session.query(FileMetadata).get(file_id)
    if file:
        file_content = parser.from_file(file.path)
        return jsonify({
            'metadata': {
                'id': file.id,
                'path': file.path,
                'size': file.size,
                'modification_date': file.modification_date,
                'category': file.category,
                'inferred_category': file.inferred_category,
                'keywords': file.keywords,
                'summary': file.summary,
                'pe_info': file.pe_info
            },
            'content': file_content['content']
        })
    else:
        with queue_lock:
            scan_queue.append(file.path)
        return jsonify({'error': 'File not found, added to scan queue'}), 404

# Route to serve the HTML file
@app.route('/')
def serve_html():
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
 
    WEB_IP = '0.0.0.0'
    WEB_PORT = 5000
    # app run - till canceled
    app.run(port=WEB_PORT, host=WEB_IP, debug=True, use_reloader=False)


