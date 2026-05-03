"""Postgres connection + ORM models matching common/migrations/0001_init.sql.

The schema is owned by the SQL migration; SQLAlchemy here is for
read/write code paths in the indexer and server. Do NOT use
Base.metadata.create_all() in production - apply the SQL migration first
so pgvector indexes (HNSW) are created with their proper opclasses.
"""

import os
from typing import Optional

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

try:
    from pgvector.sqlalchemy import Vector
except ImportError as exc:  # pragma: no cover - import guard for clearer error
    raise ImportError(
        "pgvector is required. Install with: pip install pgvector"
    ) from exc


SCHEMA = "meta_server"

Base = declarative_base()


def _embed_dim() -> int:
    raw = os.getenv("EMBED_DIM")
    if not raw:
        raise ValueError(
            "EMBED_DIM is required (must match the dim used when "
            "0001_init.sql was applied)."
        )
    return int(raw)


# Resolved once at import time; keeping this module-level so the ORM
# Vector(...) columns can use it.
EMBED_DIM = _embed_dim()


class Document(Base):
    __tablename__ = "documents"
    __table_args__ = {"schema": SCHEMA}

    id = Column(BigInteger, primary_key=True)
    path = Column(Text, unique=True, nullable=False)
    size = Column(BigInteger, nullable=False)
    modification_date = Column(Float, nullable=False)
    origin_date = Column(Text)
    mime_type = Column(Text)
    file_type = Column(Text)
    creator_software = Column(Text)
    category = Column(Text)
    inferred_category = Column(Text)
    keywords = Column(Text)
    summary = Column(Text)
    pe_info = Column(Text)
    llm_provider = Column(Text)
    llm_model = Column(Text)
    embed_model = Column(Text)
    indexed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    chunks = relationship("Chunk", back_populates="document", cascade="all, delete-orphan")


class Topic(Base):
    __tablename__ = "topics"
    __table_args__ = {"schema": SCHEMA}

    id = Column(BigInteger, primary_key=True)
    name = Column(Text, unique=True, nullable=False)
    description = Column(Text)
    centroid = Column(Vector(EMBED_DIM))
    embed_model = Column(Text, nullable=False)
    doc_count = Column(Integer, nullable=False, default=0)
    chunk_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    chunks = relationship("Chunk", back_populates="topic")


class TopicEdge(Base):
    __tablename__ = "topic_edges"
    __table_args__ = (
        PrimaryKeyConstraint("src_topic_id", "dst_topic_id", "kind"),
        CheckConstraint("kind IN ('cooccurs', 'similar', 'parent', 'related')", name="topic_edges_kind_check"),
        CheckConstraint("src_topic_id <> dst_topic_id", name="topic_edges_no_self_check"),
        {"schema": SCHEMA},
    )

    src_topic_id = Column(BigInteger, ForeignKey(f"{SCHEMA}.topics.id", ondelete="CASCADE"), nullable=False)
    dst_topic_id = Column(BigInteger, ForeignKey(f"{SCHEMA}.topics.id", ondelete="CASCADE"), nullable=False)
    kind = Column(Text, nullable=False)
    weight = Column(Float, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Chunk(Base):
    __tablename__ = "chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "chunk_idx", name="chunks_document_chunk_idx_key"),
        {"schema": SCHEMA},
    )

    id = Column(BigInteger, primary_key=True)
    document_id = Column(BigInteger, ForeignKey(f"{SCHEMA}.documents.id", ondelete="CASCADE"), nullable=False)
    topic_id = Column(BigInteger, ForeignKey(f"{SCHEMA}.topics.id", ondelete="SET NULL"))
    chunk_idx = Column(Integer, nullable=False)
    aspect = Column(Text)
    text = Column(Text, nullable=False)
    char_start = Column(Integer)
    char_end = Column(Integer)
    embedding = Column(Vector(EMBED_DIM), nullable=False)
    embed_model = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    document = relationship("Document", back_populates="chunks")
    topic = relationship("Topic", back_populates="chunks")


class IndexQueueItem(Base):
    __tablename__ = "index_queue"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'in_progress', 'done', 'error')",
            name="index_queue_status_check",
        ),
        {"schema": SCHEMA},
    )

    id = Column(BigInteger, primary_key=True)
    file_path = Column(Text, unique=True, nullable=False)
    status = Column(Text, nullable=False, default="pending")
    error = Column(Text)
    added_at = Column(Float)
    started_at = Column(Float)
    finished_at = Column(Float)


def make_engine(database_url: Optional[str] = None):
    url = database_url or os.getenv("DATABASE_URL")
    if not url:
        raise ValueError(
            "DATABASE_URL is required, e.g. "
            "postgresql+psycopg://user:pass@localhost:5432/docbase"
        )
    return create_engine(url, future=True)


def make_session_factory(engine=None):
    engine = engine or make_engine()
    return sessionmaker(bind=engine, future=True, expire_on_commit=False)
