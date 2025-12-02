"""Base LLM Provider Abstract Class"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Standard response format for LLM operations"""
    category: Optional[str] = None
    keywords: Optional[str] = None
    summary: Optional[str] = None
    raw_response: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


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
