"""Anthropic Claude LLM Provider Implementation"""

import logging
from typing import Dict, List, Optional
from .base import BaseLLMProvider, LLMResponse, EmbeddingResponse

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None

log = logging.getLogger(__name__)


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude API provider implementation"""

    def __init__(self, api_key: str, model: str = "claude-3-5-haiku-20241022", **kwargs):
        """
        Initialize Anthropic provider

        Args:
            api_key: Anthropic API key
            model: Model to use (default: claude-3-5-haiku-20241022)
            **kwargs: Additional configuration
        """
        super().__init__(api_key, model, **kwargs)

        if Anthropic is None:
            raise ImportError("anthropic package is not installed. Install with: pip install anthropic")

        self.client = Anthropic(api_key=api_key)
        self.timeout = kwargs.get('timeout', 30)
        self.max_retries = kwargs.get('max_retries', 3)

    def infer_category_and_keywords(
        self,
        content: str,
        language: str = 'en',
        file_path: Optional[str] = None
    ) -> LLMResponse:
        """
        Use Claude to infer category, extract keywords, and generate summary

        Args:
            content: Text content to analyze
            language: Language of the content
            file_path: Optional file path for context

        Returns:
            LLMResponse with category, keywords, and summary
        """
        try:
            prompt = self._build_inference_prompt(content, language, file_path)

            response = self.client.messages.create(
                model=self.model,
                max_tokens=500,
                temperature=0.3,
                system="You are a document analysis assistant. Analyze the provided content and extract structured information.",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=self.timeout
            )

            result_text = response.content[0].text
            parsed = self._parse_inference_response(result_text)

            return LLMResponse(
                category=parsed.get('category'),
                keywords=parsed.get('keywords'),
                summary=parsed.get('summary'),
                raw_response=result_text,
                metadata={
                    'model': self.model,
                    'provider': 'anthropic',
                    'input_tokens': response.usage.input_tokens if hasattr(response, 'usage') else None,
                    'output_tokens': response.usage.output_tokens if hasattr(response, 'usage') else None
                }
            )

        except Exception as e:
            log.error(f"Anthropic inference failed: {e}")
            raise

    def generate_embedding(self, content: str) -> EmbeddingResponse:
        """
        Generate embeddings - Note: Anthropic doesn't provide native embeddings

        This will raise NotImplementedError. For embeddings with Anthropic,
        consider using a separate embedding provider like Voyage AI or OpenAI.

        Args:
            content: Text content to embed

        Returns:
            EmbeddingResponse with embedding vector
        """
        raise NotImplementedError(
            "Anthropic does not provide native embedding endpoints. "
            "Use OpenAI or Ollama for embeddings, or integrate a dedicated embedding service like Voyage AI."
        )

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Generic chat completion using Claude

        Args:
            messages: List of message dictionaries
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Response text
        """
        try:
            # Extract system message if present
            system_msg = None
            user_messages = []

            for msg in messages:
                if msg['role'] == 'system':
                    system_msg = msg['content']
                else:
                    user_messages.append(msg)

            kwargs = {
                'model': self.model,
                'messages': user_messages,
                'temperature': temperature,
                'timeout': self.timeout
            }

            if system_msg:
                kwargs['system'] = system_msg

            if max_tokens:
                kwargs['max_tokens'] = max_tokens
            else:
                kwargs['max_tokens'] = 1024

            response = self.client.messages.create(**kwargs)

            return response.content[0].text

        except Exception as e:
            log.error(f"Anthropic chat completion failed: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test Anthropic connection

        Returns:
            True if connection is successful
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=5,
                messages=[{"role": "user", "content": "test"}],
                timeout=10
            )
            return response.content[0].text is not None

        except Exception as e:
            log.error(f"Anthropic connection test failed: {e}")
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
        """Parse the structured response from Claude"""
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
