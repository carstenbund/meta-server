#!/usr/bin/env python3
"""
Modernized Index Worker using LLM Provider Abstraction

This worker processes files from the index queue using configurable LLM providers
(OpenAI, Anthropic, or Ollama) for document analysis and categorization.
"""

import os
import sys
import time
import threading
import logging
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError
from langdetect import detect
from langdetect.lang_detect_exception import LangDetectException
from tika import parser
import magic
import pefile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MyLogger import Logger
from llm_providers import get_llm_provider
from llm_providers.factory import ProviderConfig, list_available_providers

# ---------- Configuration ----------
DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///instance/files.db')
NUM_WORKERS = int(os.getenv('NUM_WORKERS', '4'))
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '2'))  # seconds

# LLM Provider Configuration
LLM_PROVIDER = os.getenv('LLM_PROVIDER')  # Optional: specify provider explicitly
ENABLE_EMBEDDINGS = os.getenv('ENABLE_EMBEDDINGS', 'false').lower() == 'true'

# ---------- Logger Setup ----------
log = Logger(log_name='index_worker_llm', log_level=logging.DEBUG).get_logger()

# ---------- SQLAlchemy Setup ----------
Base = declarative_base()
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

# ---------- Models ----------
class FileMetadata(Base):
    __tablename__ = 'file_metadata'
    from sqlalchemy import Column, Integer, String, Float, Text
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
    # New fields for LLM tracking
    llm_provider = Column(String)
    llm_model = Column(String)
    embedding_vector = Column(Text)  # JSON-encoded vector


class IndexQueue(Base):
    __tablename__ = 'index_queue'
    from sqlalchemy import Column, Integer, String, Float, Text
    id = Column(Integer, primary_key=True)
    file_path = Column(String, unique=True, nullable=False)
    status = Column(String, default='pending')  # pending, in_progress, done, error
    error = Column(Text, nullable=True)
    added_at = Column(Float)
    started_at = Column(Float)
    finished_at = Column(Float)


# ---------- Helper Functions ----------
def detect_file_type(file_path):
    """Detect MIME type and file type using magic"""
    file_magic = magic.Magic(mime=True)
    mime_type = file_magic.from_file(file_path)
    parts = mime_type.split('/')
    file_type = parts[0]
    creator_software = parts[1] if len(parts) > 1 else 'Unknown'
    return mime_type, file_type, creator_software


def get_pe_info(file_path):
    """Extract PE (Windows executable) information"""
    try:
        pe = pefile.PE(file_path)
        return str({
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "number_of_sections": pe.FILE_HEADER.NumberOfSections
        })
    except Exception as e:
        return str(e)


def clean_text(text):
    """Clean and normalize text content"""
    import re
    text = re.sub(r'\n+', '\n', text)
    text = text.strip()
    return re.sub(r'\s+', ' ', text)


# ---------- Indexing Worker Thread ----------
class IndexWorker(threading.Thread):
    """Worker thread that processes files from the index queue"""

    def __init__(self, worker_id, llm_provider):
        """
        Initialize worker

        Args:
            worker_id: Unique worker identifier
            llm_provider: LLM provider instance
        """
        super().__init__()
        self.worker_id = worker_id
        self.running = True
        self.llm_provider = llm_provider
        log.info(f"Worker-{worker_id} initialized with provider: {llm_provider.get_provider_name()}")

    def run(self):
        """Main worker loop"""
        log.info(f"Worker-{self.worker_id} started.")

        while self.running:
            with Session() as session:
                # Get next pending job
                job = session.execute(
                    select(IndexQueue)
                    .where(IndexQueue.status == 'pending')
                    .limit(1)
                ).scalar_one_or_none()

                if not job:
                    time.sleep(POLL_INTERVAL)
                    continue

                log.debug(f"Worker-{self.worker_id} processing {job.file_path}")
                job.status = 'in_progress'
                job.started_at = time.time()
                session.commit()

                try:
                    self.process_file(session, job)
                    job.status = 'done'
                    job.finished_at = time.time()
                    session.commit()
                    log.info(f"Worker-{self.worker_id} indexed {job.file_path}")
                except Exception as e:
                    job.status = 'error'
                    job.error = str(e)
                    job.finished_at = time.time()
                    session.commit()
                    log.error(f"Worker-{self.worker_id} failed on {job.file_path}: {e}")

    def process_file(self, session, job):
        """
        Process a single file using the LLM provider

        Args:
            session: SQLAlchemy session
            job: IndexQueue job record
        """
        path = job.file_path
        if not os.path.exists(path):
            raise FileNotFoundError(f"File does not exist: {path}")

        size = os.path.getsize(path)
        mod_time = os.path.getmtime(path)
        origin_date = str(mod_time)
        mime_type, file_type, creator_software = detect_file_type(path)
        category = os.path.basename(os.path.dirname(path))
        pe_info = ""
        content = ""
        inferred_category = None
        keywords = None
        summary = None
        embedding_vector = None

        ext = os.path.splitext(path)[1].lower()

        # Process based on file type
        if ext == ".exe":
            pe_info = get_pe_info(path)
            content = pe_info
            inferred_category = "Executable"

        elif ext in [".pdf", ".doc", ".docx", ".txt"]:
            # Extract text content
            if ext == ".txt":
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except Exception as e:
                    log.warning(f"Failed to read text file {path}: {e}")
                    content = ""
            else:
                parsed = parser.from_file(path)
                content = parsed.get("content", "") if parsed else ""

            content = clean_text(content)

            if content:
                # Detect language
                try:
                    lang = detect(content[:500])
                except LangDetectException:
                    lang = "unknown"

                # Use LLM provider for inference
                try:
                    response = self.llm_provider.infer_category_and_keywords(
                        content=content[:1000],  # Use first 1000 chars
                        language=lang,
                        file_path=path
                    )

                    inferred_category = response.category
                    keywords = response.keywords
                    summary = response.summary

                    log.debug(f"LLM inference successful for {path}: category={inferred_category}")

                    # Generate embeddings if enabled
                    if ENABLE_EMBEDDINGS:
                        try:
                            emb_response = self.llm_provider.generate_embedding(content[:8000])
                            # Store as JSON string
                            import json
                            embedding_vector = json.dumps(emb_response.embedding)
                            log.debug(f"Generated embedding for {path} (dim={len(emb_response.embedding)})")
                        except NotImplementedError:
                            log.debug(f"Embeddings not supported by {self.llm_provider.get_provider_name()}")
                        except Exception as e:
                            log.warning(f"Failed to generate embedding for {path}: {e}")

                except Exception as e:
                    log.error(f"LLM inference failed for {path}: {e}")
                    # Continue with partial metadata

        else:
            # Other file types - just extract content
            parsed = parser.from_file(path)
            content = parsed.get("content", "") if parsed else ""
            content = clean_text(content)

        # Create or update metadata
        metadata = FileMetadata(
            path=path,
            size=size,
            modification_date=mod_time,
            category=category,
            inferred_category=inferred_category,
            keywords=keywords,
            summary=summary,
            content=summary if summary else content[:5000],  # Store summary or truncated content
            file_type=file_type,
            creator_software=creator_software,
            origin_date=origin_date,
            pe_info=pe_info,
            llm_provider=self.llm_provider.get_provider_name(),
            llm_model=self.llm_provider.model,
            embedding_vector=embedding_vector
        )
        session.merge(metadata)


# ---------- Entrypoint ----------
def main():
    """Main entry point for the index worker"""
    log.info("=" * 60)
    log.info("Starting Index Worker with LLM Provider Abstraction")
    log.info("=" * 60)

    # Initialize provider configuration
    provider_config = ProviderConfig()

    # Log available providers
    available = list_available_providers(provider_config)
    log.info(f"Available providers: {available}")

    # Get LLM provider
    try:
        llm_provider = get_llm_provider(provider_name=LLM_PROVIDER, config=provider_config)
        log.info(f"Using LLM provider: {llm_provider.get_provider_name()}")
        log.info(f"Model: {llm_provider.model}")
        log.info(f"Embeddings enabled: {ENABLE_EMBEDDINGS}")
    except Exception as e:
        log.error(f"Failed to initialize LLM provider: {e}")
        log.error("Please configure at least one provider:")
        log.error("  - Set OPENAI_API_KEY for OpenAI")
        log.error("  - Set ANTHROPIC_API_KEY for Anthropic")
        log.error("  - Ensure Ollama is running at OLLAMA_BASE_URL")
        sys.exit(1)

    # Create database tables
    Base.metadata.create_all(engine)

    # Start workers
    log.info(f"Starting {NUM_WORKERS} worker threads...")
    workers = [IndexWorker(i, llm_provider) for i in range(NUM_WORKERS)]
    for w in workers:
        w.start()

    log.info("Index worker service is running. Press Ctrl+C to stop.")

    # Main loop
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        log.info("Stopping all workers...")
        for w in workers:
            w.running = False
        for w in workers:
            w.join()
        log.info("Index worker service stopped.")


if __name__ == '__main__':
    main()
