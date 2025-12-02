"""Ollama Local LLM Provider Implementation"""

import logging
import requests
from typing import Dict, List, Optional
from .base import BaseLLMProvider, LLMResponse, EmbeddingResponse

log = logging.getLogger(__name__)


class OllamaProvider(BaseLLMProvider):
    """Ollama local LLM provider implementation"""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2", embedding_model: str = "nomic-embed-text", **kwargs):
        """
        Initialize Ollama provider

        Args:
            base_url: Base URL for Ollama API (default: http://localhost:11434)
            model: Model to use for chat completions (default: llama3.2)
            embedding_model: Model to use for embeddings (default: nomic-embed-text)
            **kwargs: Additional configuration
        """
        super().__init__(api_key=None, model=model, **kwargs)

        self.base_url = base_url.rstrip('/')
        self.embedding_model = embedding_model
        self.timeout = kwargs.get('timeout', 60)  # Ollama can be slower
        self.max_retries = kwargs.get('max_retries', 3)

    def infer_category_and_keywords(
        self,
        content: str,
        language: str = 'en',
        file_path: Optional[str] = None
    ) -> LLMResponse:
        """
        Use Ollama to infer category, extract keywords, and generate summary

        Args:
            content: Text content to analyze
            language: Language of the content
            file_path: Optional file path for context

        Returns:
            LLMResponse with category, keywords, and summary
        """
        try:
            prompt = self._build_inference_prompt(content, language, file_path)

            response = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a document analysis assistant. Analyze the provided content and extract structured information."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 500
                    }
                },
                timeout=self.timeout
            )

            response.raise_for_status()
            result_data = response.json()
            result_text = result_data.get('message', {}).get('content', '')

            parsed = self._parse_inference_response(result_text)

            return LLMResponse(
                category=parsed.get('category'),
                keywords=parsed.get('keywords'),
                summary=parsed.get('summary'),
                raw_response=result_text,
                metadata={
                    'model': self.model,
                    'provider': 'ollama',
                    'eval_count': result_data.get('eval_count'),
                    'prompt_eval_count': result_data.get('prompt_eval_count')
                }
            )

        except Exception as e:
            log.error(f"Ollama inference failed: {e}")
            raise

    def generate_embedding(self, content: str) -> EmbeddingResponse:
        """
        Generate embeddings using Ollama

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

            response = requests.post(
                f"{self.base_url}/api/embed",
                json={
                    "model": self.embedding_model,
                    "input": content
                },
                timeout=self.timeout
            )

            response.raise_for_status()
            result_data = response.json()

            # Ollama returns embeddings in the 'embeddings' field (note: plural)
            embeddings = result_data.get('embeddings', [])
            if not embeddings:
                raise ValueError("No embeddings returned from Ollama")

            return EmbeddingResponse(
                embedding=embeddings[0],  # First embedding for single input
                model=self.embedding_model,
                metadata={
                    'provider': 'ollama',
                    'total_duration': result_data.get('total_duration'),
                    'load_duration': result_data.get('load_duration')
                }
            )

        except Exception as e:
            log.error(f"Ollama embedding failed: {e}")
            raise

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Generic chat completion using Ollama

        Args:
            messages: List of message dictionaries
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Response text
        """
        try:
            options = {
                "temperature": temperature
            }

            if max_tokens:
                options["num_predict"] = max_tokens

            response = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": options
                },
                timeout=self.timeout
            )

            response.raise_for_status()
            result_data = response.json()

            return result_data.get('message', {}).get('content', '')

        except Exception as e:
            log.error(f"Ollama chat completion failed: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Test Ollama connection

        Returns:
            True if connection is successful
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=10
            )
            response.raise_for_status()

            # Check if the model is available
            models = response.json().get('models', [])
            model_names = [m.get('name', '') for m in models]

            if self.model not in model_names:
                log.warning(f"Model {self.model} not found in Ollama. Available models: {model_names}")
                return False

            return True

        except Exception as e:
            log.error(f"Ollama connection test failed: {e}")
            return False

    def list_models(self) -> List[str]:
        """
        List available models in Ollama

        Returns:
            List of model names
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=10
            )
            response.raise_for_status()

            models = response.json().get('models', [])
            return [m.get('name', '') for m in models]

        except Exception as e:
            log.error(f"Failed to list Ollama models: {e}")
            return []

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
