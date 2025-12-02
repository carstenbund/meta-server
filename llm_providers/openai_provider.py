"""OpenAI LLM Provider Implementation"""

import logging
from typing import Dict, List, Optional
from .base import BaseLLMProvider, LLMResponse, EmbeddingResponse

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

log = logging.getLogger(__name__)


class OpenAIProvider(BaseLLMProvider):
    """OpenAI API provider implementation"""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", embedding_model: str = "text-embedding-3-small", **kwargs):
        """
        Initialize OpenAI provider

        Args:
            api_key: OpenAI API key
            model: Model to use for chat completions (default: gpt-4o-mini)
            embedding_model: Model to use for embeddings (default: text-embedding-3-small)
            **kwargs: Additional configuration
        """
        super().__init__(api_key, model, **kwargs)

        if OpenAI is None:
            raise ImportError("openai package is not installed. Install with: pip install openai")

        self.client = OpenAI(api_key=api_key)
        self.embedding_model = embedding_model
        self.timeout = kwargs.get('timeout', 30)
        self.max_retries = kwargs.get('max_retries', 3)

    def infer_category_and_keywords(
        self,
        content: str,
        language: str = 'en',
        file_path: Optional[str] = None
    ) -> LLMResponse:
        """
        Use OpenAI to infer category, extract keywords, and generate summary

        Args:
            content: Text content to analyze
            language: Language of the content
            file_path: Optional file path for context

        Returns:
            LLMResponse with category, keywords, and summary
        """
        try:
            prompt = self._build_inference_prompt(content, language, file_path)

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a document analysis assistant. Analyze the provided content and extract structured information."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500,
                timeout=self.timeout
            )

            result_text = response.choices[0].message.content
            parsed = self._parse_inference_response(result_text)

            return LLMResponse(
                category=parsed.get('category'),
                keywords=parsed.get('keywords'),
                summary=parsed.get('summary'),
                raw_response=result_text,
                metadata={
                    'model': self.model,
                    'provider': 'openai',
                    'tokens_used': response.usage.total_tokens if hasattr(response, 'usage') else None
                }
            )

        except Exception as e:
            log.error(f"OpenAI inference failed: {e}")
            raise

    def generate_embedding(self, content: str) -> EmbeddingResponse:
        """
        Generate embeddings using OpenAI

        Args:
            content: Text content to embed

        Returns:
            EmbeddingResponse with embedding vector
        """
        try:
            # Truncate content if too long
            max_chars = 8000
            if len(content) > max_chars:
                content = content[:max_chars]

            response = self.client.embeddings.create(
                model=self.embedding_model,
                input=content,
                timeout=self.timeout
            )

            return EmbeddingResponse(
                embedding=response.data[0].embedding,
                model=self.embedding_model,
                metadata={
                    'provider': 'openai',
                    'tokens_used': response.usage.total_tokens if hasattr(response, 'usage') else None
                }
            )

        except Exception as e:
            log.error(f"OpenAI embedding failed: {e}")
            raise

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Generic chat completion using OpenAI

        Args:
            messages: List of message dictionaries
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Response text
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=self.timeout
            )

            return response.choices[0].message.content

        except Exception as e:
            log.error(f"OpenAI chat completion failed: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test OpenAI connection

        Returns:
            True if connection is successful
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5,
                timeout=10
            )
            return response.choices[0].message.content is not None

        except Exception as e:
            log.error(f"OpenAI connection test failed: {e}")
            return False

    def _build_inference_prompt(self, content: str, language: str, file_path: Optional[str] = None) -> str:
        """Build the prompt for inference"""
        context = f"File: {file_path}\n" if file_path else ""
        return f"""{context}Language: {language}

Analyze the following document content and provide:
1. Category (one word or short phrase describing the document type/topic)
2. Keywords (comma-separated list of 5-10 important keywords)
3. Summary (2-3 sentence summary of the content)

Content:
{content[:1000]}

Respond in this format:
Category: [category]
Keywords: [keyword1, keyword2, ...]
Summary: [summary]"""

    def _parse_inference_response(self, response: str) -> Dict[str, str]:
        """Parse the structured response from the LLM"""
        result = {}
        lines = response.strip().split('\n')

        for line in lines:
            if line.startswith('Category:'):
                result['category'] = line.replace('Category:', '').strip()
            elif line.startswith('Keywords:'):
                result['keywords'] = line.replace('Keywords:', '').strip()
            elif line.startswith('Summary:'):
                result['summary'] = line.replace('Summary:', '').strip()

        return result
