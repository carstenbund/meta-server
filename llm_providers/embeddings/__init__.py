"""Role-based embedding adapter layer.

Different consumers in the pipeline need different embeddings:

  INDEX_DOC        - chunk text being stored in chunks.embedding
  INDEX_TOPIC      - topic name+description seeding topics.centroid
  QUERY            - user search query (asymmetric pair with INDEX_DOC)
  TOPIC_CANDIDATE  - fast prefilter against topics.centroid during indexing
  TOPIC_REFINE     - optional second-pass embedding (off by default)

Design A: one canonical dim per deployment. Every enabled role must produce
vectors of the same dimension as the column was created with at migration
apply time. Asymmetric retrieval is supported via per-role text prefixes
(e.g. "query: " / "passage: " for E5-style models), not different-dim models.
"""

from .base import BaseEmbedder, EmbeddingRole, EmbeddingResult
from .factory import EmbedderRegistry, build_registry

__all__ = [
    "BaseEmbedder",
    "EmbeddingRole",
    "EmbeddingResult",
    "EmbedderRegistry",
    "build_registry",
]
