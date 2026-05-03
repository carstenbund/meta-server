"""Ollama embedder adapter."""

import logging
from typing import List, Optional

import requests

from .base import BaseEmbedder, EmbeddingRole

log = logging.getLogger(__name__)

_KNOWN_DIMS = {
    "nomic-embed-text": 768,
    "mxbai-embed-large": 1024,
    "snowflake-arctic-embed": 1024,
    "all-minilm": 384,
    "bge-m3": 1024,
}


class OllamaEmbedder(BaseEmbedder):
    def __init__(
        self,
        role: EmbeddingRole,
        model: str,
        base_url: str = "http://localhost:11434",
        prefix: str = "",
        timeout: int = 60,
        max_input_chars: int = 8000,
    ):
        super().__init__(role=role, model=model, prefix=prefix, dim=_KNOWN_DIMS.get(model))
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_input_chars = max_input_chars

    @property
    def provider(self) -> str:
        return "ollama"

    def _encode_raw(self, text: str) -> List[float]:
        if len(text) > self._max_input_chars:
            text = text[: self._max_input_chars]
        response = requests.post(
            f"{self._base_url}/api/embed",
            json={"model": self.model, "input": text},
            timeout=self._timeout,
        )
        response.raise_for_status()
        embeddings = response.json().get("embeddings", [])
        if not embeddings:
            raise ValueError(f"No embeddings returned from Ollama for model {self.model}")
        return embeddings[0]
