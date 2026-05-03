"""Retrieval service - the canonical RAG/topic-graph API.

Transport-agnostic. HTTP routes, MCP tools, the inference_server's chat
path - any consumer instantiates RetrievalService(session, embedders)
and calls these methods. All return plain dataclasses, never Flask
objects, so adapters can serialize however they like.

To add a new transport:
  1. Build the request payload into the typed args below.
  2. Open a SQLAlchemy session via common.db.make_session_factory().
  3. Construct RetrievalService(session, embedders, llm=optional).
  4. Call search_chunks / topic_neighbors / ask.
  5. Serialize the dataclass result into your transport's wire format.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Iterable, List, Optional

from sqlalchemy import select

from common.db import Chunk, Document, Topic, TopicEdge
from llm_providers.base import BaseLLMProvider
from llm_providers.embeddings import EmbedderRegistry, EmbeddingRole

log = logging.getLogger(__name__)


@dataclass
class SearchFilters:
    file_type: Optional[str] = None
    inferred_category: Optional[str] = None
    category: Optional[str] = None
    topic_ids: Optional[List[int]] = None


@dataclass
class ChunkHit:
    chunk_id: int
    document_id: int
    topic_id: Optional[int]
    topic_name: Optional[str]
    chunk_idx: int
    aspect: Optional[str]
    text: str
    path: str
    summary: Optional[str]
    inferred_category: Optional[str]
    score: float  # cosine similarity in [-1, 1]; closer to 1 == more similar

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TopicNeighbor:
    topic_id: int
    name: str
    description: Optional[str]
    kind: str
    weight: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Citation:
    chunk_id: int
    document_id: int
    topic_id: Optional[int]
    topic_name: Optional[str]
    path: str
    score: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AskResult:
    answer: str
    citations: List[Citation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"answer": self.answer, "citations": [c.to_dict() for c in self.citations]}


class RetrievalService:
    def __init__(
        self,
        session,
        embedders: EmbedderRegistry,
        llm: Optional[BaseLLMProvider] = None,
    ):
        self.session = session
        self.embedders = embedders
        self.llm = llm

    # ---- semantic search -----------------------------------------------------

    def search_chunks(
        self,
        query: str,
        top_k: int = 10,
        filters: Optional[SearchFilters] = None,
    ) -> List[ChunkHit]:
        if not query or not query.strip():
            return []

        embedder = self.embedders.get(EmbeddingRole.QUERY)
        qvec = embedder.encode(query).embedding

        distance = Chunk.embedding.cosine_distance(qvec)
        stmt = (
            select(
                Chunk.id,
                Chunk.document_id,
                Chunk.topic_id,
                Chunk.chunk_idx,
                Chunk.aspect,
                Chunk.text,
                distance.label("distance"),
                Document.path,
                Document.summary,
                Document.inferred_category,
                Topic.name.label("topic_name"),
            )
            .join(Document, Chunk.document_id == Document.id)
            .outerjoin(Topic, Chunk.topic_id == Topic.id)
        )
        if filters:
            if filters.file_type:
                stmt = stmt.where(Document.file_type == filters.file_type)
            if filters.inferred_category:
                stmt = stmt.where(Document.inferred_category == filters.inferred_category)
            if filters.category:
                stmt = stmt.where(Document.category == filters.category)
            if filters.topic_ids:
                stmt = stmt.where(Chunk.topic_id.in_(filters.topic_ids))
        stmt = stmt.order_by(distance).limit(top_k)

        return [
            ChunkHit(
                chunk_id=r.id,
                document_id=r.document_id,
                topic_id=r.topic_id,
                topic_name=r.topic_name,
                chunk_idx=r.chunk_idx,
                aspect=r.aspect,
                text=r.text,
                path=r.path,
                summary=r.summary,
                inferred_category=r.inferred_category,
                score=1.0 - float(r.distance),
            )
            for r in self.session.execute(stmt).all()
        ]

    # ---- topic graph ---------------------------------------------------------

    def topic_neighbors(
        self,
        topic_id: int,
        kinds: Optional[Iterable[str]] = None,
        limit: int = 20,
    ) -> List[TopicNeighbor]:
        stmt = (
            select(
                TopicEdge.dst_topic_id,
                TopicEdge.kind,
                TopicEdge.weight,
                Topic.name.label("dst_name"),
                Topic.description.label("dst_description"),
            )
            .join(Topic, Topic.id == TopicEdge.dst_topic_id)
            .where(TopicEdge.src_topic_id == topic_id)
        )
        if kinds:
            stmt = stmt.where(TopicEdge.kind.in_(list(kinds)))
        stmt = stmt.order_by(TopicEdge.weight.desc()).limit(limit)

        return [
            TopicNeighbor(
                topic_id=r.dst_topic_id,
                name=r.dst_name,
                description=r.dst_description,
                kind=r.kind,
                weight=float(r.weight),
            )
            for r in self.session.execute(stmt).all()
        ]

    # ---- end-to-end RAG ------------------------------------------------------

    def ask(
        self,
        query: str,
        top_k: int = 5,
        filters: Optional[SearchFilters] = None,
    ) -> AskResult:
        if self.llm is None:
            raise ValueError(
                "RetrievalService.ask() requires an llm provider. "
                "Pass one to RetrievalService(..., llm=...)."
            )

        hits = self.search_chunks(query, top_k=top_k, filters=filters)
        if not hits:
            return AskResult(answer="No matching documents found.", citations=[])

        # Group by topic so the prompt is organised, not a flat dump.
        grouped: dict = {}
        for h in hits:
            key = (h.topic_id, h.topic_name or "Uncategorized")
            grouped.setdefault(key, []).append(h)

        sections = []
        for (topic_id, topic_name), chunks in grouped.items():
            section = [f"## Topic: {topic_name}"]
            for c in chunks:
                section.append(
                    f"[chunk {c.chunk_id} | {c.path} | score={c.score:.2f}]\n{c.text}"
                )
            sections.append("\n".join(section))
        context = "\n\n".join(sections)

        system = (
            "You answer questions strictly from the provided document excerpts. "
            "Cite supporting chunks inline as [chunk N]. If the context does not "
            "contain the answer, say so."
        )
        user = f"Question: {query}\n\nContext:\n{context}\n\nAnswer:"
        answer = self.llm.chat_completion(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
        )

        return AskResult(
            answer=answer,
            citations=[
                Citation(
                    chunk_id=h.chunk_id,
                    document_id=h.document_id,
                    topic_id=h.topic_id,
                    topic_name=h.topic_name,
                    path=h.path,
                    score=h.score,
                )
                for h in hits
            ],
        )
