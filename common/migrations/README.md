# Database migrations

SQL migrations for the meta-server Postgres store. Apply in numeric order.

## Prerequisites

- Postgres 14+ with the `vector` extension available (pgvector). If `CREATE
  EXTENSION vector;` fails, ask your DBA to install it first — it requires
  superuser.
- A role with `CREATE` on the target database.

## Apply

```sh
export DATABASE_URL='postgresql://user:pass@localhost:5432/docbase'
psql "$DATABASE_URL" \
     -v ON_ERROR_STOP=1 \
     -v EMBED_DIM=1536 \
     -f common/migrations/0001_init.sql
```

`EMBED_DIM` is required and chosen per deployment to match whichever
embedding model your `llm_providers` adapter produces.

## Embedding dimension

The dim is committed at apply time via `-v EMBED_DIM=...`. Switching
embedding models later means dropping and recreating the embedding
columns and their HNSW indexes, then re-indexing all documents. The
`embed_model` column on `topics` and `chunks` records which model
produced each vector so drift is detectable.

| Model                                 | Dim  |
| ------------------------------------- | ---- |
| `text-embedding-3-small` (OpenAI)     | 1536 |
| `text-embedding-3-large` (OpenAI)     | 3072 |
| `nomic-embed-text` (Ollama)           | 768  |
| `mxbai-embed-large` (Ollama)          | 1024 |

## Schema

All objects live in the `meta_server` schema:

- `documents` — one row per indexed file
- `topics` — nodes in the topic web (with running centroid)
- `topic_edges` — `cooccurs` / `similar` / `parent` / `related`
- `chunks` — topic-aligned spans, one embedding each
- `index_queue` — work queue for the indexer worker
- `schema_version` — applied migration bookkeeping
