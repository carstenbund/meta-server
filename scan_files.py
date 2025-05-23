import os
import logging
import requests
import magic
import re
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from langdetect import detect
from langdetect.lang_detect_exception import LangDetectException
from tika import parser
import pefile
from MyLogger import Logger

# Create a logger instance
log = Logger(log_name='scan_files', log_level=logging.DEBUG).get_logger()

# Database setup
DATABASE_URI = 'sqlite:///instance/files.db'
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
    content = Column(String, nullable=True)
    file_type = Column(String, nullable=True)
    creator_software = Column(String, nullable=True)
    origin_date = Column(String, nullable=True)
    pe_info = Column(String, nullable=True)  # New column for PE file information

# Ensure database tables are created
Base.metadata.create_all(engine)

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

def clean_text(text):
    # Remove extra newlines
    text = re.sub(r'\n+', '\n', text)
    # Remove leading and trailing whitespace
    text = text.strip()
    # Reduce multiple spaces to a single space
    text = re.sub(r'\s+', ' ', text)
    return text

def scan_directory(directory):
    for subdir, _, files in os.walk(directory):
        for file in files:
            if file.startswith('.'):
                continue
            file_path = os.path.join(subdir, file)

            # Check if file already exists in the database
            existing_file = session.query(FileMetadata).filter_by(path=file_path).first()
            if existing_file:
                log.debug(f"File {file_path} already exists in the database, skipping.")
                continue

            file_extension = os.path.splitext(file_path)[1].lower()
            
            log.debug(f"Processing file: {file_path}")
            
            # Detect file type and creator software
            mime_type, file_type, creator_software = detect_file_type(file_path)
            log.debug(f"Detected MIME type: {mime_type}, file type: {file_type}, creator software: {creator_software}")
            
            # Log file size, modification date, and content
            size = os.path.getsize(file_path)
            modification_date = os.path.getmtime(file_path)
            log.debug(f"File size: {size}, modification date: {modification_date}")
            
            # Extract metadata using file path
            category = infer_metadata_from_path(file_path)
            log.debug(f"Inferred category from path: {category}")

            content = ""
            inferred_category = None
            keywords = None
            summary = None
            origin_date = str(modification_date)
            pe_info = ""

            if file_type == 'image':
                log.debug(f"Handling image file: {file_path}")
                inferred_category = 'Image'
            elif file_extension == '.exe':
                content = get_pe_info(file_path)
                inferred_category = 'Executable'
                log.debug(f"Extracted PE info: {content}")
            elif file_extension in ['.pdf', '.doc', '.docx']:
                log.debug(f"skipping {file_path}")
                log.debug(f"Tika parsing {file_path}")
                parsed = parser.from_file(file_path)
                inferred_category = 'Document'
                content = parsed.get('content', '') if parsed else ''
                
                if content:
                    log.debug(f"Extracted content: {content[:20]}...")  # Print first 20 characters of content

                    content = clean_text(content)

                    # Detect the language of the content
                    try:
                        source_lang = detect(content) if content else 'unknown'
                    except LangDetectException:
                        source_lang = 'unknown'
                    log.debug(f"Detected language: {source_lang}")
                    
                    payload = {
                        'file_path': file_path,
                        'content': content[:500],
                        'language': source_lang
                    }
                    
                    # Send content to inference server for processing
                    response = requests.post('http://localhost:5001/infer', json=payload)
                    if response.status_code == 200:
                        data = response.json()
                        log.debug(f"Inference server response: {data}")
                        inferred_category = data.get('category')
                        keywords = data.get('keywords')
                        summary = data.get('summary')

                        # Include the summary in the content for PDF and DOC/DOCX files
                        if file_extension in ['.pdf', '.doc', '.docx']:
                            content = summary
                    else:
                        log.debug(f"Error processing file {file_path}: {response.text}")
                else:
                    log.debug(f"No content extracted from {file_path}")
            else: 
                log.debug(f"Entering file {file_path} of type {file_type}")
                if not content:
                    log.debug(f"No content extracted from {file_path}")
            
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
            log.debug(f"Metadata for {file_path} added to database.")

if __name__ == '__main__':
    directory_to_scan = '/win95/mcrlnsalg/'
    scan_directory(directory_to_scan)
