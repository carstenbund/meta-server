# Indexing System Upgrade Recommendation (DMD)

## Context and Current Implementation
- **Indexing workers** live in `indexer/index_service.py`, polling a SQLite-backed queue and running Tika-based extraction with language detection and a locally hosted inference endpoint at `http://localhost:5001/infer` for categorization and summarization.
- The stack depends on legacy components (Apache Tika, `langdetect`, synchronous HTTP requests, and a custom inference service) that predate recent advances in LLM APIs and embedding pipelines.
- Scaling is limited by a single-process SQLite database, static worker pool, and lack of backpressure or observability hooks.

## Goals
- Modernize ingestion to use current LLM/embedding APIs (OpenAI, Ollama, or equivalent) with clearer abstractions.
- Improve scalability, reliability, and observability of the indexing workflow.
- Reduce per-file latency and failure modes from brittle parsers and monolithic workers.

## Gaps and Risks in the Existing Approach
- **Parser fragility:** Tika and `magic` often misclassify or silently drop content; no retries or structured error telemetry.
- **Synchronous inference bottleneck:** Workers block on a single inference endpoint without timeout or circuit breaking.
- **Limited language handling:** `langdetect` on truncated content can be noisy; no tokenizer-aware chunking for long documents.
- **Storage constraints:** SQLite and a flat `index_queue` table cap concurrency and complicate horizontal scaling.
- **Model obsolescence:** The inference service is unspecified and likely older; it does not exploit modern embeddings or system prompts.

## Recommended Upgrades
### 1) API Modernization
- **OpenAI Assistants/Embeddings:** Replace raw `INFERENCE_URL` calls with the official `openai` SDK (e.g., `client.responses.create` for classification/summarization or `client.embeddings.create` for semantic search). Use batch-friendly requests and structured prompts for category/keyword extraction.
- **Ollama / Local Models:** Add a provider abstraction so the worker can target OpenAI, Ollama, or other backends via a common interface. For Ollama, use the `/api/chat` and `/api/embed` endpoints with streaming enabled to avoid timeouts.
- **Timeouts and Retries:** Wrap outbound calls with timeouts, exponential backoff, and dead-lettering on repeated failure; capture provider/version metadata alongside results.

### 2) Document Processing Pipeline
- Introduce a **chunking layer** (e.g., token-based splits with overlap) to handle long documents before embedding/summarization.
- Swap Tika for **filetype-aware parsers** (PDFPlumber, python-docx, markdown/plaintext fallbacks) to reduce JVM overhead and improve fidelity.
- Normalize text with deterministic cleaning and capture source hashes for deduplication.

### 3) Storage and Queueing
- Migrate from SQLite to a **lightweight queue broker** (Redis/RQ, RabbitMQ, or SQS) plus a relational store (Postgres) for metadata. This enables horizontal worker scaling and visibility into job states.
- Version the schema to record **embedding vectors, model names, prompt templates, and provider** to support re-indexing and auditability.

### 4) Observability and Operations
- Emit structured logs/metrics (OpenTelemetry) for: parse duration, tokens billed, provider latency, retry counts, and failure reasons.
- Add health checks for upstream providers and circuit-breaker logic to fall back between OpenAI and local Ollama when one is degraded.

### 5) Security and Compliance
- Centralize secret management (environment variables + secret manager) for API keys.
- Enforce content-size limits and PII scrubbing prior to sending data to third-party APIs; keep local-only paths for sensitive data via Ollama.

## Suggested Phased Implementation
1. **Abstraction Layer:** Define a `ProviderClient` interface with concrete implementations for OpenAI and Ollama (chat + embeddings) and swap `requests.post(INFERENCE_URL, ...)` with this interface.
2. **Parsing/Chunking Module:** Replace direct Tika usage with a pluggable extractor and tokenizer-aware chunker; include deterministic tests for popular file types.
3. **Queue Migration:** Introduce Redis/RQ (or Celery) workers with visibility tooling; migrate `index_queue` semantics and add backpressure controls.
4. **Telemetry:** Wire structured logging and metrics; publish dashboards for throughput, latency, and error budgets.
5. **Re-index Path:** Add schema fields for `model`, `provider`, `embedding_version`, and `content_hash`, and a background job to re-run indexing when models change.

## Expected Outcomes
- Faster, more reliable indexing with graceful degradation between cloud and local models.
- Improved search relevance via modern embeddings and richer metadata.
- Operational visibility and re-indexing hooks that keep the corpus aligned with evolving LLM capabilities.
