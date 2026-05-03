"""Builds the per-role embedder registry from environment configuration.

Configuration shape (env):

  EMBED_DIM=1536                                  # canonical deployment dim
  EMBED_INDEX_DOC=openai:text-embedding-3-small   # required
  EMBED_INDEX_DOC_PREFIX=passage:                  # optional
  EMBED_QUERY=openai:text-embedding-3-small        # optional, defaults to INDEX_DOC
  EMBED_QUERY_PREFIX=query:                        # optional
  EMBED_INDEX_TOPIC=...                            # optional, defaults to INDEX_DOC
  EMBED_TOPIC_CANDIDATE=...                        # optional, defaults to INDEX_DOC
  EMBED_TOPIC_REFINE=...                           # optional, disabled if unset

  OPENAI_API_KEY=...
  OLLAMA_BASE_URL=http://localhost:11434

The factory enforces design A: every enabled role must produce vectors of the
same dimension as EMBED_DIM (which the SQL migration was applied with).
"""

import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional

from .base import BaseEmbedder, EmbeddingRole
from .openai_embedder import OpenAIEmbedder
from .ollama_embedder import OllamaEmbedder

log = logging.getLogger(__name__)


_ROLE_ENV = {
    EmbeddingRole.INDEX_DOC: "EMBED_INDEX_DOC",
    EmbeddingRole.INDEX_TOPIC: "EMBED_INDEX_TOPIC",
    EmbeddingRole.QUERY: "EMBED_QUERY",
    EmbeddingRole.TOPIC_CANDIDATE: "EMBED_TOPIC_CANDIDATE",
    EmbeddingRole.TOPIC_REFINE: "EMBED_TOPIC_REFINE",
}

# Roles that fall back to INDEX_DOC's spec when their own env var is unset.
# TOPIC_REFINE has no fallback: unset means disabled.
_FALLBACK_TO_INDEX_DOC = {
    EmbeddingRole.INDEX_TOPIC,
    EmbeddingRole.QUERY,
    EmbeddingRole.TOPIC_CANDIDATE,
}


@dataclass
class _Spec:
    provider: str
    model: str
    prefix: str


def _parse_spec(raw: str, prefix: str) -> _Spec:
    if ":" not in raw:
        raise ValueError(
            f"Embedder spec must be 'provider:model' (got {raw!r}). "
            "Example: openai:text-embedding-3-small"
        )
    provider, model = raw.split(":", 1)
    return _Spec(provider=provider.strip().lower(), model=model.strip(), prefix=prefix)


def _build_embedder(role: EmbeddingRole, spec: _Spec) -> BaseEmbedder:
    if spec.provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(f"OPENAI_API_KEY required for role {role.value}")
        return OpenAIEmbedder(role=role, model=spec.model, api_key=api_key, prefix=spec.prefix)
    if spec.provider == "ollama":
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        return OllamaEmbedder(role=role, model=spec.model, base_url=base_url, prefix=spec.prefix)
    raise ValueError(f"Unknown embedder provider {spec.provider!r} for role {role.value}")


class EmbedderRegistry:
    """Holds the configured embedder for each role and validates compatibility."""

    def __init__(self, embedders: Dict[EmbeddingRole, BaseEmbedder], canonical_dim: int):
        self._embedders = embedders
        self._canonical_dim = canonical_dim

    @property
    def canonical_dim(self) -> int:
        return self._canonical_dim

    def get(self, role: EmbeddingRole) -> BaseEmbedder:
        try:
            return self._embedders[role]
        except KeyError:
            raise KeyError(
                f"No embedder configured for role {role.value}. "
                f"Set {_ROLE_ENV[role]} or rely on its INDEX_DOC fallback."
            )

    def has(self, role: EmbeddingRole) -> bool:
        return role in self._embedders

    def roles(self):
        return list(self._embedders.keys())


def build_registry(canonical_dim: Optional[int] = None) -> EmbedderRegistry:
    canonical_dim = canonical_dim if canonical_dim is not None else _read_canonical_dim()

    index_raw = os.getenv(_ROLE_ENV[EmbeddingRole.INDEX_DOC])
    if not index_raw:
        raise ValueError(
            f"{_ROLE_ENV[EmbeddingRole.INDEX_DOC]} is required "
            "(e.g. 'openai:text-embedding-3-small')."
        )
    index_spec = _parse_spec(
        index_raw,
        prefix=os.getenv(f"{_ROLE_ENV[EmbeddingRole.INDEX_DOC]}_PREFIX", ""),
    )

    embedders: Dict[EmbeddingRole, BaseEmbedder] = {}
    for role, env_name in _ROLE_ENV.items():
        raw = os.getenv(env_name)
        prefix = os.getenv(f"{env_name}_PREFIX", "")
        if raw:
            spec = _parse_spec(raw, prefix=prefix)
        elif role in _FALLBACK_TO_INDEX_DOC:
            spec = _Spec(provider=index_spec.provider, model=index_spec.model, prefix=prefix)
        else:
            continue  # disabled
        embedders[role] = _build_embedder(role, spec)

    _validate_dims(embedders, canonical_dim)
    log.info(
        "Embedder registry: dim=%d, roles=%s",
        canonical_dim,
        {role.value: f"{e.provider}:{e.model}" for role, e in embedders.items()},
    )
    return EmbedderRegistry(embedders=embedders, canonical_dim=canonical_dim)


def _read_canonical_dim() -> int:
    raw = os.getenv("EMBED_DIM")
    if not raw:
        raise ValueError(
            "EMBED_DIM is required (must match the dim used when 0001_init.sql was applied)."
        )
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"EMBED_DIM must be an integer, got {raw!r}") from exc


def _validate_dims(embedders: Dict[EmbeddingRole, BaseEmbedder], canonical_dim: int) -> None:
    """Design A: every enabled role must produce vectors of canonical_dim."""
    for role, embedder in embedders.items():
        try:
            actual = embedder.dim
        except Exception as exc:
            raise ValueError(
                f"Could not determine dim for role {role.value} "
                f"({embedder.provider}:{embedder.model}): {exc}"
            ) from exc
        if actual != canonical_dim:
            raise ValueError(
                f"Embedder dim mismatch: role {role.value} "
                f"({embedder.provider}:{embedder.model}) produces dim={actual}, "
                f"but EMBED_DIM={canonical_dim}. Either pick a matching model or "
                f"re-apply the migration with -v EMBED_DIM={actual}."
            )
