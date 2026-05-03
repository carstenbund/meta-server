#!/usr/bin/env python3
"""Index worker - topic-graph aware, Postgres-backed.

Reads pending jobs from meta_server.index_queue, parses each file, runs
the combined LLM extraction (category + keywords + summary + topic
spans), embeds each span via the INDEX_DOC role embedder, and writes
documents/chunks/topics/topic_edges into Postgres.

Concurrency: each worker thread holds its own SQLAlchemy session. Job
pickup uses SELECT ... FOR UPDATE SKIP LOCKED so multiple workers can
share the same queue without colliding.
"""

import logging
import os
import sys
import threading
import time
import traceback
from typing import Optional

import magic
import pefile
from langdetect import detect
from langdetect.lang_detect_exception import LangDetectException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from tika import parser as tika_parser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MyLogger import Logger
from common.db import (
    Chunk,
    Document,
    IndexQueueItem,
    Topic,
    make_engine,
    make_session_factory,
)
from document_preprocessor import preprocess_for_embedding, preprocess_for_llm
from indexer.topic_resolver import TopicResolver
from llm_providers import get_llm_provider
from llm_providers.embeddings import EmbeddingRole, build_registry
from llm_providers.factory import ProviderConfig

log = Logger(log_name="index_worker", log_level=logging.DEBUG).get_logger()


NUM_WORKERS = int(os.getenv("NUM_WORKERS", "4"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "2"))
LLM_PROVIDER = os.getenv("LLM_PROVIDER")
CANDIDATE_TOP_K = int(os.getenv("TOPIC_CANDIDATE_TOP_K", "30"))
LLM_INPUT_CHARS = int(os.getenv("LLM_INPUT_CHARS", "8000"))
SPAN_EMBED_CHARS = int(os.getenv("SPAN_EMBED_CHARS", "4000"))


# ---------- helpers ----------

def detect_file_type(path: str):
    mime_type = magic.Magic(mime=True).from_file(path)
    parts = mime_type.split("/", 1)
    return mime_type, parts[0], parts[1] if len(parts) > 1 else "Unknown"


def get_pe_info(path: str) -> str:
    try:
        pe = pefile.PE(path)
        return str(
            {
                "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                "image_base": pe.OPTIONAL_HEADER.ImageBase,
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            }
        )
    except Exception as exc:
        return f"pefile_error: {exc}"


def read_text_content(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".txt":
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except Exception as exc:
            log.warning("Failed to read text file %s: %s", path, exc)
            return ""
    parsed = tika_parser.from_file(path)
    return (parsed or {}).get("content", "") or ""


# ---------- worker thread ----------

class IndexWorker(threading.Thread):
    def __init__(self, worker_id: int, session_factory, llm, embedders):
        super().__init__(daemon=True)
        self.worker_id = worker_id
        self.session_factory = session_factory
        self.llm = llm
        self.embedders = embedders
        self.running = True

    def run(self) -> None:
        log.info("Worker-%d started (provider=%s)", self.worker_id, self.llm.get_provider_name())
        while self.running:
            job_id = self._claim_next_job()
            if job_id is None:
                time.sleep(POLL_INTERVAL)
                continue
            self._process_job(job_id)

    def _claim_next_job(self) -> Optional[int]:
        """Atomically transition one pending row to in_progress and return its id."""
        with self.session_factory() as session:
            job = session.execute(
                select(IndexQueueItem)
                .where(IndexQueueItem.status == "pending")
                .order_by(IndexQueueItem.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).scalar_one_or_none()
            if job is None:
                return None
            job.status = "in_progress"
            job.started_at = time.time()
            session.commit()
            return job.id

    def _process_job(self, job_id: int) -> None:
        with self.session_factory() as session:
            job = session.get(IndexQueueItem, job_id)
            if job is None:
                return
            try:
                self._index_file(session, job.file_path)
                job.status = "done"
                job.error = None
                job.finished_at = time.time()
                session.commit()
                log.info("Worker-%d indexed %s", self.worker_id, job.file_path)
            except Exception as exc:
                session.rollback()
                log.exception("Worker-%d failed on %s: %s", self.worker_id, job.file_path, exc)
                with self.session_factory() as err_session:
                    err_job = err_session.get(IndexQueueItem, job_id)
                    if err_job is not None:
                        err_job.status = "error"
                        err_job.error = f"{exc}\n{traceback.format_exc()}"[:8000]
                        err_job.finished_at = time.time()
                        err_session.commit()

    # ---- core indexing ----

    def _index_file(self, session, path: str) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(path)

        size = os.path.getsize(path)
        mod_time = os.path.getmtime(path)
        mime_type, file_type, creator = detect_file_type(path)
        category = os.path.basename(os.path.dirname(path))

        ext = os.path.splitext(path)[1].lower()
        pe_info: Optional[str] = None
        raw_content = ""
        if ext == ".exe":
            pe_info = get_pe_info(path)
            raw_content = pe_info
        else:
            raw_content = read_text_content(path)

        cleaned_for_llm = preprocess_for_llm(
            raw_content, max_chars=LLM_INPUT_CHARS, aggressive_cleaning=True
        ) if raw_content else ""

        try:
            language = detect(raw_content[:500]) if raw_content else "unknown"
        except LangDetectException:
            language = "unknown"

        resolver = TopicResolver(session, self.embedders)
        candidates = (
            resolver.prefilter_candidates(cleaned_for_llm, top_k=CANDIDATE_TOP_K)
            if cleaned_for_llm
            else []
        )

        response = None
        if cleaned_for_llm:
            try:
                response = self.llm.extract_with_topics(
                    cleaned_for_llm,
                    candidate_topics=candidates,
                    language=language,
                    file_path=path,
                )
            except Exception as exc:
                log.error("LLM extraction failed for %s: %s", path, exc)
                response = None

        index_doc_embedder = self.embedders.get(EmbeddingRole.INDEX_DOC)

        document = self._upsert_document(
            session,
            path=path,
            size=size,
            mod_time=mod_time,
            mime_type=mime_type,
            file_type=file_type,
            creator=creator,
            category=category,
            response=response,
            pe_info=pe_info,
            embed_model=index_doc_embedder.model,
        )
        # Wipe old chunks for this document on re-index.
        session.query(Chunk).filter(Chunk.document_id == document.id).delete(synchronize_session=False)

        seen_topic_ids: list[int] = []
        if response is not None:
            for idx, span in enumerate(response.topics):
                resolved = resolver.resolve(span)
                topic = resolved.topic

                span_text = (span.span_text or "").strip()
                if not span_text:
                    span_text = f"{span.name}. {span.description or ''}".strip()
                span_text = preprocess_for_embedding(span_text, max_chars=SPAN_EMBED_CHARS) or span_text

                emb = index_doc_embedder.encode(span_text)
                session.add(
                    Chunk(
                        document_id=document.id,
                        topic_id=topic.id,
                        chunk_idx=idx,
                        aspect=span.aspect,
                        text=span_text,
                        char_start=span.char_start,
                        char_end=span.char_end,
                        embedding=emb.embedding,
                        embed_model=emb.model,
                    )
                )
                resolver.absorb_chunk(topic, emb.embedding)
                if topic.id not in seen_topic_ids:
                    resolver.link_document(topic)
                    seen_topic_ids.append(topic.id)

        resolver.record_cooccurrences(seen_topic_ids)
        session.flush()

    def _upsert_document(
        self,
        session,
        *,
        path: str,
        size: int,
        mod_time: float,
        mime_type: str,
        file_type: str,
        creator: str,
        category: str,
        response,
        pe_info: Optional[str],
        embed_model: str,
    ) -> Document:
        category_inferred = response.category if response else None
        keywords = response.keywords if response else None
        summary = response.summary if response else None
        llm_meta = (response.metadata or {}) if response else {}

        values = dict(
            path=path,
            size=size,
            modification_date=mod_time,
            origin_date=str(mod_time),
            mime_type=mime_type,
            file_type=file_type,
            creator_software=creator,
            category=category,
            inferred_category=category_inferred,
            keywords=keywords,
            summary=summary,
            pe_info=pe_info,
            llm_provider=llm_meta.get("provider") or self.llm.get_provider_name(),
            llm_model=llm_meta.get("model") or self.llm.model,
            embed_model=embed_model,
        )

        stmt = pg_insert(Document.__table__).values(**values)
        update_cols = {k: stmt.excluded[k] for k in values if k != "path"}
        stmt = stmt.on_conflict_do_update(index_elements=["path"], set_=update_cols).returning(Document.__table__.c.id)
        doc_id = session.execute(stmt).scalar_one()
        return session.get(Document, doc_id)


# ---------- entrypoint ----------

def main() -> None:
    log.info("=" * 60)
    log.info("Index worker (Postgres / topic graph) starting")
    log.info("=" * 60)

    engine = make_engine()
    session_factory = make_session_factory(engine)

    try:
        embedders = build_registry()
    except Exception as exc:
        log.error("Failed to build embedder registry: %s", exc)
        sys.exit(1)

    try:
        llm = get_llm_provider(provider_name=LLM_PROVIDER, config=ProviderConfig())
    except Exception as exc:
        log.error("Failed to initialize LLM provider: %s", exc)
        sys.exit(1)

    log.info("LLM provider: %s (model=%s)", llm.get_provider_name(), llm.model)
    log.info("Embedder roles: %s", {r.value: f"{embedders.get(r).provider}:{embedders.get(r).model}" for r in embedders.roles()})
    log.info("Canonical embedding dim: %d", embedders.canonical_dim)

    workers = [IndexWorker(i, session_factory, llm, embedders) for i in range(NUM_WORKERS)]
    for w in workers:
        w.start()
    log.info("Spawned %d worker threads", NUM_WORKERS)

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        log.info("Stopping workers...")
        for w in workers:
            w.running = False
        for w in workers:
            w.join(timeout=10)


if __name__ == "__main__":
    main()
