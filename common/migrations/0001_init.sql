-- 0001_init.sql
-- Initial schema for the meta-server topic-graph + RAG store.
--
-- EMBED_DIM is required and must match the embedding model your chosen
-- llm_providers adapter produces (e.g. 1536 for text-embedding-3-small,
-- 768 for nomic-embed-text). It is committed at apply time:
--
--   psql "$DATABASE_URL" \
--        -v ON_ERROR_STOP=1 \
--        -v EMBED_DIM=1536 \
--        -f common/migrations/0001_init.sql
--
-- Switching embedding models later means dropping and recreating the
-- embedding columns and their HNSW indexes, then re-indexing.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE SCHEMA IF NOT EXISTS meta_server;
SET search_path TO meta_server, public;

-- ---------------------------------------------------------------------------
-- documents: one row per indexed file. Replaces the SQLite file_metadata.
-- ---------------------------------------------------------------------------
CREATE TABLE meta_server.documents (
    id                 BIGSERIAL PRIMARY KEY,
    path               TEXT        NOT NULL UNIQUE,
    size               BIGINT      NOT NULL,
    modification_date  DOUBLE PRECISION NOT NULL,
    origin_date        TEXT,
    mime_type          TEXT,
    file_type          TEXT,
    creator_software   TEXT,
    category           TEXT,                  -- folder-derived
    inferred_category  TEXT,                  -- LLM-derived
    keywords           TEXT,
    summary            TEXT,
    pe_info            TEXT,
    llm_provider       TEXT,
    llm_model          TEXT,
    embed_model        TEXT,
    indexed_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX documents_inferred_category_idx ON meta_server.documents (inferred_category);
CREATE INDEX documents_file_type_idx         ON meta_server.documents (file_type);

-- ---------------------------------------------------------------------------
-- topics: nodes in the topic web. Centroid is the running mean of the
-- embeddings of all chunks assigned to the topic, used to (a) prefilter
-- candidate topics for new documents and (b) compute `similar` edges.
-- ---------------------------------------------------------------------------
CREATE TABLE meta_server.topics (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT        NOT NULL UNIQUE,
    description   TEXT,
    centroid      vector(:EMBED_DIM),
    embed_model   TEXT        NOT NULL,
    doc_count     INTEGER     NOT NULL DEFAULT 0,
    chunk_count   INTEGER     NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX topics_centroid_idx
    ON meta_server.topics
    USING hnsw (centroid vector_cosine_ops);

-- ---------------------------------------------------------------------------
-- topic_edges: the "web of topics".
--   cooccurs : incremented at index time when two topics appear in the
--              same document.
--   similar  : recomputed offline by ANN over topic centroids.
--   parent   : reserved for future LLM-asserted hierarchy.
--   related  : reserved for future LLM-asserted associations.
-- ---------------------------------------------------------------------------
CREATE TABLE meta_server.topic_edges (
    src_topic_id  BIGINT      NOT NULL REFERENCES meta_server.topics(id) ON DELETE CASCADE,
    dst_topic_id  BIGINT      NOT NULL REFERENCES meta_server.topics(id) ON DELETE CASCADE,
    kind          TEXT        NOT NULL CHECK (kind IN ('cooccurs', 'similar', 'parent', 'related')),
    weight        DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (src_topic_id, dst_topic_id, kind),
    CHECK (src_topic_id <> dst_topic_id)
);

CREATE INDEX topic_edges_dst_idx ON meta_server.topic_edges (dst_topic_id, kind);

-- ---------------------------------------------------------------------------
-- chunks: topic-aligned spans of a document, each with its own embedding.
-- A document produces N chunks where N == number of topics the LLM
-- extraction pass identified for it.
-- ---------------------------------------------------------------------------
CREATE TABLE meta_server.chunks (
    id           BIGSERIAL PRIMARY KEY,
    document_id  BIGINT      NOT NULL REFERENCES meta_server.documents(id) ON DELETE CASCADE,
    topic_id     BIGINT               REFERENCES meta_server.topics(id)    ON DELETE SET NULL,
    chunk_idx    INTEGER     NOT NULL,
    aspect       TEXT,                  -- 'definition' | 'method' | 'result' | 'context' | ...
    text         TEXT        NOT NULL,
    char_start   INTEGER,
    char_end     INTEGER,
    embedding    vector(:EMBED_DIM) NOT NULL,
    embed_model  TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (document_id, chunk_idx)
);

CREATE INDEX chunks_document_idx  ON meta_server.chunks (document_id);
CREATE INDEX chunks_topic_idx     ON meta_server.chunks (topic_id);
CREATE INDEX chunks_embedding_idx
    ON meta_server.chunks
    USING hnsw (embedding vector_cosine_ops);

-- ---------------------------------------------------------------------------
-- index_queue: work queue consumed by the indexer worker. Mirrors the
-- existing SQLite table so the scanner side can be ported with no schema
-- surprises.
-- ---------------------------------------------------------------------------
CREATE TABLE meta_server.index_queue (
    id           BIGSERIAL PRIMARY KEY,
    file_path    TEXT        NOT NULL UNIQUE,
    status       TEXT        NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'in_progress', 'done', 'error')),
    error        TEXT,
    added_at     DOUBLE PRECISION,
    started_at   DOUBLE PRECISION,
    finished_at  DOUBLE PRECISION
);

CREATE INDEX index_queue_status_idx ON meta_server.index_queue (status)
    WHERE status IN ('pending', 'in_progress');

-- ---------------------------------------------------------------------------
-- schema_version: trivial bookkeeping so future migrations can no-op cleanly.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS meta_server.schema_version (
    version     INTEGER     PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO meta_server.schema_version (version) VALUES (1)
ON CONFLICT (version) DO NOTHING;
