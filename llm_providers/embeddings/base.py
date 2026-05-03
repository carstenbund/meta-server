"""Embedder role enum and abstract base class."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class EmbeddingRole(str, Enum):
    INDEX_DOC = "index_doc"
    INDEX_TOPIC = "index_topic"
    QUERY = "query"
    TOPIC_CANDIDATE = "topic_candidate"
    TOPIC_REFINE = "topic_refine"


@dataclass
class EmbeddingResult:
    embedding: List[float]
    model: str
    role: EmbeddingRole
    provider: str
    metadata: dict = field(default_factory=dict)


class BaseEmbedder(ABC):
    """Abstract embedder bound to a single (role, provider, model)."""

    def __init__(
        self,
        role: EmbeddingRole,
        model: str,
        prefix: str = "",
        dim: Optional[int] = None,
    ):
        self.role = role
        self.model = model
        self.prefix = prefix
        self._dim = dim

    @property
    @abstractmethod
    def provider(self) -> str:
        ...

    @property
    def dim(self) -> int:
        if self._dim is None:
            self._dim = self._probe_dim()
        return self._dim

    def _probe_dim(self) -> int:
        result = self._encode_raw("dim probe")
        return len(result)

    def encode(self, text: str) -> EmbeddingResult:
        prepared = f"{self.prefix}{text}" if self.prefix else text
        vector = self._encode_raw(prepared)
        return EmbeddingResult(
            embedding=vector,
            model=self.model,
            role=self.role,
            provider=self.provider,
            metadata={"prefix": self.prefix} if self.prefix else {},
        )

    @abstractmethod
    def _encode_raw(self, text: str) -> List[float]:
        ...
