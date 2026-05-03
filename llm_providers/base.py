"""Base LLM Provider Abstract Class"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class TopicSpan:
    """A topic the LLM identified in a document, with the supporting span.

    `name` is the topic label (existing or new). `description` is a short
    natural-language explanation used to seed the topic's centroid when
    the topic is new. `span_text` is the verbatim passage that justifies
    the assignment; char_start/char_end are offsets into the document
    text passed to the extractor (best-effort; LLMs aren't always exact).
    `aspect` classifies what kind of mention this is, e.g. 'definition',
    'method', 'result', 'context'.
    """
    name: str
    description: str
    span_text: str
    aspect: Optional[str] = None
    char_start: Optional[int] = None
    char_end: Optional[int] = None


@dataclass
class LLMResponse:
    """Standard response format for LLM operations"""
    category: Optional[str] = None
    keywords: Optional[str] = None
    summary: Optional[str] = None
    topics: List[TopicSpan] = field(default_factory=list)
    raw_response: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class TopicCandidate:
    """An existing topic offered to the LLM as a candidate during extraction."""
    name: str
    description: Optional[str] = None


@dataclass
class EmbeddingResponse:
    """Standard response format for embedding operations"""
    embedding: List[float]
    model: str
    metadata: Optional[Dict[str, Any]] = None


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, **kwargs):
        """
        Initialize the LLM provider

        Args:
            api_key: API key for the provider (optional for local models like Ollama)
            model: Model name to use
            **kwargs: Additional provider-specific configuration
        """
        self.api_key = api_key
        self.model = model
        self.config = kwargs

    @abstractmethod
    def infer_category_and_keywords(
        self,
        content: str,
        language: str = 'en',
        file_path: Optional[str] = None
    ) -> LLMResponse:
        """
        Infer category, extract keywords, and generate summary from content

        Args:
            content: Text content to analyze
            language: Language of the content
            file_path: Optional file path for context

        Returns:
            LLMResponse with category, keywords, and summary
        """
        pass

    def extract_with_topics(
        self,
        content: str,
        candidate_topics: Optional[List[TopicCandidate]] = None,
        language: str = 'en',
        file_path: Optional[str] = None,
    ) -> LLMResponse:
        """Combined extraction: category, keywords, summary, AND topic spans.

        Default implementation falls back to infer_category_and_keywords with
        no topics. Providers override this to do everything in one call.

        candidate_topics is the prefiltered list of existing topics the LLM
        should prefer to assign to (or it can propose new names).
        """
        return self.infer_category_and_keywords(content, language=language, file_path=file_path)

    @abstractmethod
    def generate_embedding(self, content: str) -> EmbeddingResponse:
        """
        Generate embeddings for the given content

        Args:
            content: Text content to embed

        Returns:
            EmbeddingResponse with embedding vector
        """
        pass

    @abstractmethod
    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Generic chat completion interface

        Args:
            messages: List of message dictionaries with 'role' and 'content'
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Response text
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test if the provider is available and properly configured

        Returns:
            True if connection is successful, False otherwise
        """
        pass

    def get_provider_name(self) -> str:
        """Get the name of this provider"""
        return self.__class__.__name__.replace('Provider', '')
