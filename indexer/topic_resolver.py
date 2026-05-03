"""Topic resolver: prefilters candidates, dedups names, updates centroids, edges.

Used by the index worker. Operates on a single SQLAlchemy session; the caller
decides commit boundaries (typically once per document).

Design A invariants:
  - All embeddings (centroids, chunk embeddings, candidate-prefilter probes)
    share the deployment EMBED_DIM.
  - Cooccurrence edges are stored in BOTH directions for symmetric queries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from itertools import combinations
from typing import List, Optional, Sequence

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from common.db import Topic, TopicEdge
from llm_providers.base import TopicCandidate, TopicSpan
from llm_providers.embeddings import EmbedderRegistry, EmbeddingRole

log = logging.getLogger(__name__)

DEFAULT_CANDIDATE_TOP_K = 30
DEFAULT_MERGE_THRESHOLD = 0.92  # cosine similarity above which two names merge


@dataclass
class ResolvedTopic:
    topic: Topic
    is_new: bool


class TopicResolver:
    def __init__(
        self,
        session,
        embedders: EmbedderRegistry,
        merge_threshold: float = DEFAULT_MERGE_THRESHOLD,
    ):
        self.session = session
        self.embedders = embedders
        self.merge_threshold = merge_threshold

    # ---- candidate prefilter --------------------------------------------------

    def prefilter_candidates(
        self, query_text: str, top_k: int = DEFAULT_CANDIDATE_TOP_K
    ) -> List[TopicCandidate]:
        """Return the top-K existing topics nearest to query_text.

        Uses the TOPIC_CANDIDATE role embedder (falls back to INDEX_DOC's spec
        unless overridden). Returns [] when no topics exist yet (cold start).
        """
        embedder = self.embedders.get(EmbeddingRole.TOPIC_CANDIDATE)
        probe = embedder.encode(query_text).embedding
        rows = self.session.execute(
            select(Topic.name, Topic.description)
            .where(Topic.centroid.is_not(None))
            .order_by(Topic.centroid.cosine_distance(probe))
            .limit(top_k)
        ).all()
        return [TopicCandidate(name=r.name, description=r.description) for r in rows]

    # ---- find-or-create -------------------------------------------------------

    def resolve(self, span: TopicSpan) -> ResolvedTopic:
        """Find or create the Topic for an LLM-proposed TopicSpan.

        1. Exact case-insensitive name match -> reuse.
        2. Otherwise embed name+description and ANN-search centroids; if the
           nearest is within merge_threshold cosine similarity, reuse.
        3. Otherwise create a new topic seeded with the name embedding.
        """
        normalized = span.name.strip()
        if not normalized:
            raise ValueError("TopicSpan.name must be non-empty")

        existing = self.session.execute(
            select(Topic).where(func.lower(Topic.name) == normalized.lower())
        ).scalar_one_or_none()
        if existing:
            return ResolvedTopic(topic=existing, is_new=False)

        embedder = self.embedders.get(EmbeddingRole.INDEX_TOPIC)
        seed_text = normalized
        if span.description:
            seed_text = f"{normalized}. {span.description.strip()}"
        seed_vec = embedder.encode(seed_text).embedding

        nearest = self.session.execute(
            select(Topic, Topic.centroid.cosine_distance(seed_vec).label("dist"))
            .where(Topic.centroid.is_not(None))
            .order_by(Topic.centroid.cosine_distance(seed_vec))
            .limit(1)
        ).first()
        if nearest is not None:
            topic, dist = nearest
            if (1.0 - float(dist)) >= self.merge_threshold:
                log.debug(
                    "Merging proposed topic %r into existing %r (sim=%.3f)",
                    normalized, topic.name, 1.0 - float(dist),
                )
                return ResolvedTopic(topic=topic, is_new=False)

        new_topic = Topic(
            name=normalized,
            description=span.description or None,
            centroid=seed_vec,
            embed_model=embedder.model,
            doc_count=0,
            chunk_count=0,
        )
        self.session.add(new_topic)
        self.session.flush()  # populate id
        return ResolvedTopic(topic=new_topic, is_new=True)

    # ---- centroid + counts ----------------------------------------------------

    def absorb_chunk(self, topic: Topic, chunk_embedding: Sequence[float]) -> None:
        """Fold a new chunk embedding into the topic's running centroid.

        For chunk_count == 0 the centroid is replaced (the name-seed is just
        a placeholder until real content arrives). Afterwards it's a
        running mean: new = (old * n + v) / (n + 1).
        """
        chunk_vec = np.asarray(chunk_embedding, dtype=np.float32)
        n = int(topic.chunk_count or 0)
        if n == 0 or topic.centroid is None:
            topic.centroid = chunk_vec.tolist()
        else:
            old = np.asarray(topic.centroid, dtype=np.float32)
            topic.centroid = ((old * n + chunk_vec) / (n + 1)).tolist()
        topic.chunk_count = n + 1
        topic.updated_at = func.now()

    def link_document(self, topic: Topic) -> None:
        topic.doc_count = int(topic.doc_count or 0) + 1

    # ---- cooccurrence edges ---------------------------------------------------

    def record_cooccurrences(self, topic_ids: Sequence[int]) -> None:
        """Increment cooccurs weight for every distinct pair, both directions."""
        unique_ids = sorted({int(t) for t in topic_ids})
        if len(unique_ids) < 2:
            return
        edges_table = TopicEdge.__table__
        for a, b in combinations(unique_ids, 2):
            for src, dst in ((a, b), (b, a)):
                stmt = pg_insert(edges_table).values(
                    src_topic_id=src,
                    dst_topic_id=dst,
                    kind="cooccurs",
                    weight=1.0,
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=["src_topic_id", "dst_topic_id", "kind"],
                    set_={
                        "weight": edges_table.c.weight + 1,
                        "updated_at": func.now(),
                    },
                )
                self.session.execute(stmt)
