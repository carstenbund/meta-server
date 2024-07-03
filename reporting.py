import os
import logging
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

# Configure logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Database setup
DATABASE_URI = 'sqlite:///instance/files.db'
Base = declarative_base()
engine = create_engine(DATABASE_URI, echo=True)  # Enable SQL statement logging
Session = sessionmaker(bind=engine)
session = Session()

# Define the FileMetadata model (assuming this is already defined)
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

# Function to generate stats per section (directory)
def stats_per_section():
    results = session.query(
        FileMetadata.category,
        func.count(FileMetadata.id).label('file_count'),
        func.sum(FileMetadata.size).label('total_size'),
        func.avg(FileMetadata.size).label('average_size')
    ).group_by(FileMetadata.category).all()

    print("Stats per section (directory):")
    for result in results:
        print(f"Section: {result.category}, File Count: {result.file_count}, Total Size: {result.total_size}, Average Size: {result.average_size}")

# Function to generate stats per file type
def stats_per_filetype():
    results = session.query(
        FileMetadata.file_type,
        func.substr(FileMetadata.path, -3).label('file_extension'),
        func.count(FileMetadata.id).label('file_count'),
        func.sum(FileMetadata.size).label('total_size'),
        func.avg(FileMetadata.size).label('average_size')
    ).group_by(FileMetadata.file_type, func.substr(FileMetadata.path, -3).label('file_extension')).all()

    print("Stats per file type:")
    for result in results:
        print(f"File Type: {result.file_type} {result.file_extension}, File Count: {result.file_count}, Total Size: {result.total_size}, Average Size: {result.average_size}")

if __name__ == '__main__':
    #stats_per_section()
    stats_per_filetype()

