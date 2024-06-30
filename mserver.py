from flask import Flask, jsonify, request, send_from_directory
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float
from flask_cors import CORS
import os
import threading
import time
import requests  # Used to communicate with the Tika server

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
    content = Column(String, nullable=False)

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

# Function to extract text using Tika server
def extract_text_with_tika(file_path):
    with open(file_path, 'rb') as file:
        response = requests.put('http://localhost:9998/tika', files={'file': file})
        if response.status_code == 200:
            return response.text
        else:
            return ""

# Function to scan and update a single file
def scan_and_update_file(file_path):
    session = Session()
    content = extract_text_with_tika(file_path)

    # Implement the scanning logic
    metadata = FileMetadata(
        path=file_path,
        size=os.path.getsize(file_path),
        modification_date=os.path.getmtime(file_path),
        content=content
    )
    session.add(metadata)
    session.commit()
    session.close()

# Endpoint to list files in a directory
@app.route('/files', methods=['GET'])
def list_files():
    directory = request.args.get('directory', '/')
    files = []
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        files.append({
            'path': file_path,
            'is_directory': os.path.isdir(file_path),
            'id': filename if os.path.isfile(file_path) else None
        })
    return jsonify(files)

# Endpoint to get file details and content
@app.route('/files/<path:file_id>', methods=['GET'])
def get_file(file_id):
    file = session.query(FileMetadata).filter_by(path=file_id).first()
    if file:
        return jsonify({
            'metadata': {
                'id': file.id,
                'path': file.path,
                'size': file.size,
                'modification_date': file.modification_date,
                'category': file.category,
                'inferred_category': file.inferred_category,
                'keywords': file.keywords,
                'summary': file.summary
            },
            'content': file.content
        })
    else:
        with queue_lock:
            scan_queue.append(file_id)
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



