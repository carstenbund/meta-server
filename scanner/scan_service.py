import os
import time
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import IntegrityError
from MyLogger import Logger

# ---------- Configuration ----------
DATABASE_URI = 'sqlite:///instance/files.db'
SCAN_DIRECTORY = '/win95/mcrlnsalg'
SCAN_INTERVAL = 60  # in seconds

# Ensure instance directory exists
os.makedirs(os.path.dirname(DATABASE_URI.replace('sqlite:///', '')), exist_ok=True)

# ---------- Logger Setup ----------
log = Logger(log_name='scan_service', log_level=logging.DEBUG).get_logger()

# ---------- SQLAlchemy Setup ----------
Base = declarative_base()
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

# ---------- Models ----------
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
    status = Column(String, default='pending')  # pending, in_progress, done, error
    error = Column(Text, nullable=True)
    added_at = Column(Float)
    started_at = Column(Float)
    finished_at = Column(Float)


# ---------- Staleness Check ----------
def is_file_stale_or_incomplete(file_path, metadata: FileMetadata) -> (bool, str):
    try:
        disk_mtime = os.path.getmtime(file_path)
    except FileNotFoundError:
        return False, "File no longer exists"

    if disk_mtime > metadata.modification_date:
        return True, "Modified since last index"

    if not metadata.content:
        return True, "Missing content"
    if not metadata.inferred_category:
        return True, "Missing inferred_category"
    if not metadata.summary:
        return True, "Missing summary"

    return False, ""


# ---------- Main Scan Logic ----------
def scan_and_queue(session, directory):
    log.info(f"Starting scan cycle for {directory}")
    for subdir, _, files in os.walk(directory):
        for filename in files:
            if filename.startswith('.') or os.path.islink(filename):
                continue

            file_path = os.path.abspath(os.path.join(subdir, filename))

            # Attempt to get modification time first
            try:
                disk_mod_time = os.path.getmtime(file_path)
                file_size = os.path.getsize(file_path)
            except FileNotFoundError:
                log.warning(f"Skipped (file vanished): {file_path}")
                continue

            # Check DB for existing record
            existing = session.query(FileMetadata).filter_by(path=file_path).first()
            needs_queue = False
            reason = ""

            if not existing:
                needs_queue = True
                reason = "Not indexed yet"
            else:
                stale, reason = is_file_stale_or_incomplete(file_path, existing)
                needs_queue = stale

            if needs_queue:
                already_queued = session.query(IndexQueue).filter_by(file_path=file_path).first()
                if already_queued:
                    log.debug(f"Already queued: {file_path}")
                    continue

                try:
                    session.add(IndexQueue(
                        file_path=file_path,
                        status='pending',
                        added_at=time.time()
                    ))
                    session.commit()
                    log.info(f"Queued for indexing: {file_path} ({reason})")
                except IntegrityError:
                    session.rollback()
                    log.debug(f"Queue conflict (already exists): {file_path}")
            else:
                log.debug(f"Up-to-date: {file_path}")


# ---------- Continuous Service ----------
def run_scan_service(directory, interval):
    log.info("Initializing database...")
    Base.metadata.create_all(engine)
    log.debug(f"Watching directory: {directory}")
    log.debug(f"Using database: {DATABASE_URI}")

    try:
        while True:
            with Session() as session:
                scan_and_queue(session, directory)
            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("Scan service terminated by user.")
    except Exception as e:
        log.exception(f"Fatal error in scan service: {e}")


# ---------- Entrypoint ----------
if __name__ == '__main__':
    run_scan_service(SCAN_DIRECTORY, SCAN_INTERVAL)
