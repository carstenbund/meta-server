# Database migrations

SQL migrations for the meta-server Postgres store. Apply in numeric order.

## Prerequisites

- Postgres 14+ with the `vector` extension available (pgvector). If `CREATE
  EXTENSION vector;` fails, ask your DBA to install it first — it requires
  superuser.
- A role with `CREATE` on the target database.

## Apply

```sh
export DATABASE_URL='postgresql://user:pass@host:5432/meta'
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f common/migrations/0001_init.sql
```

## Embedding dimension

`0001_init.sql` declares `vector(1536)` (OpenAI `text-embedding-3-small`). To
use a different model, edit the `\set EMBED_DIM` line at the top **before
applying**. Changing it later means dropping and recreating the embedding
columns and their HNSW indexes, then re-indexing all documents.

| Model                                 | Dim  |
| ------------------------------------- | ---- |
| `text-embedding-3-small` (OpenAI)     | 1536 |
| `text-embedding-3-large` (OpenAI)     | 3072 |
| `nomic-embed-text` (Ollama)           | 768  |
| `mxbai-embed-large` (Ollama)          | 1024 |

## Schema

All objects live in the `meta` schema:

- `documents` — one row per indexed file
- `topics` — nodes in the topic web (with running centroid)
- `topic_edges` — `cooccurs` / `similar` / `parent` / `related`
- `chunks` — topic-aligned spans, one embedding each
- `index_queue` — work queue for the indexer worker
- `schema_version` — applied migration bookkeeping
