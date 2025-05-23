# models.py

from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Float, Text

Base = declarative_base()

class FileMetadata(Base):
    __tablename__ = 'file_metadata'
    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(String, unique=True, nullable=False)
    size = Column(Integer, nullable=False)
    modification_date = Column(Float, nullable=False)
    category = Column(String)
    inferred_category = Column(String)
    keywords = Column(String)
    summary = Column(String)
    content = Column(Text)
    file_type = Column(String)
    creator_software = Column(String)
    origin_date = Column(String)
    pe_info = Column(Text)

class IndexQueue(Base):
    __tablename__ = 'index_queue'
    id = Column(Integer, primary_key=True)
    file_path = Column(String, unique=True, nullable=False)
    status = Column(String, default='pending')
    error = Column(Text)
    added_at = Column(Float)
    started_at = Column(Float)
    finished_at = Column(Float)

