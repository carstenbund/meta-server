"""OpenAI embedder adapter."""

import logging
from typing import List, Optional

from openai import OpenAI

from .base import BaseEmbedder, EmbeddingRole

log = logging.getLogger(__name__)

# Known fixed dimensions for OpenAI embedding models. Used to validate the
# deployment EMBED_DIM at startup without making a network call.
_KNOWN_DIMS = {
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
    "text-embedding-ada-002": 1536,
}


class OpenAIEmbedder(BaseEmbedder):
    def __init__(
        self,
        role: EmbeddingRole,
        model: str,
        api_key: str,
        prefix: str = "",
        timeout: int = 60,
        max_input_chars: int = 8000,
    ):
        super().__init__(role=role, model=model, prefix=prefix, dim=_KNOWN_DIMS.get(model))
        self._client = OpenAI(api_key=api_key, timeout=timeout)
        self._max_input_chars = max_input_chars

    @property
    def provider(self) -> str:
        return "openai"

    def _encode_raw(self, text: str) -> List[float]:
        if len(text) > self._max_input_chars:
            text = text[: self._max_input_chars]
        response = self._client.embeddings.create(model=self.model, input=text)
        return response.data[0].embedding
