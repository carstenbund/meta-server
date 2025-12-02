"""LLM Provider Factory - Token-key based provider selection"""

import os
import logging
from typing import Optional, Dict, Any
from .base import BaseLLMProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama_provider import OllamaProvider

log = logging.getLogger(__name__)


class ProviderConfig:
    """Configuration for LLM providers"""

    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        """
        Initialize provider configuration

        Args:
            config_dict: Optional configuration dictionary
        """
        if config_dict is None:
            config_dict = {}

        # Provider selection priority
        self.openai_api_key = config_dict.get('openai_api_key') or os.getenv('OPENAI_API_KEY')
        self.anthropic_api_key = config_dict.get('anthropic_api_key') or os.getenv('ANTHROPIC_API_KEY')
        self.ollama_base_url = config_dict.get('ollama_base_url') or os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')

        # Model configurations
        self.openai_model = config_dict.get('openai_model') or os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
        self.openai_embedding_model = config_dict.get('openai_embedding_model') or os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small')

        self.anthropic_model = config_dict.get('anthropic_model') or os.getenv('ANTHROPIC_MODEL', 'claude-3-5-haiku-20241022')

        self.ollama_model = config_dict.get('ollama_model') or os.getenv('OLLAMA_MODEL', 'llama3.2')
        self.ollama_embedding_model = config_dict.get('ollama_embedding_model') or os.getenv('OLLAMA_EMBEDDING_MODEL', 'nomic-embed-text')

        # Provider preference order (can be overridden)
        self.provider_preference = config_dict.get('provider_preference') or os.getenv('LLM_PROVIDER_PREFERENCE', 'openai,anthropic,ollama')

        # Additional options
        self.timeout = int(config_dict.get('timeout') or os.getenv('LLM_TIMEOUT', '60'))
        self.max_retries = int(config_dict.get('max_retries') or os.getenv('LLM_MAX_RETRIES', '3'))

        # Fallback behavior
        self.enable_fallback = config_dict.get('enable_fallback', True)


def get_llm_provider(
    provider_name: Optional[str] = None,
    config: Optional[ProviderConfig] = None,
    **kwargs
) -> BaseLLMProvider:
    """
    Factory function to get the appropriate LLM provider based on token-key settings

    Selection logic:
    1. If provider_name is specified, use that provider
    2. Otherwise, check for API keys in order of preference
    3. Fall back to next available provider if preferred one fails

    Args:
        provider_name: Explicit provider name ('openai', 'anthropic', 'ollama')
        config: ProviderConfig instance (will create default if not provided)
        **kwargs: Additional provider-specific configuration

    Returns:
        Configured LLM provider instance

    Raises:
        ValueError: If no provider is available or configured
    """
    if config is None:
        config = ProviderConfig()

    # If explicit provider requested, return that
    if provider_name:
        return _create_provider(provider_name, config, **kwargs)

    # Otherwise, try providers in preference order
    preference_order = [p.strip().lower() for p in config.provider_preference.split(',')]

    for provider in preference_order:
        try:
            instance = _create_provider(provider, config, **kwargs)

            # Test connection if fallback is enabled
            if config.enable_fallback:
                if instance.test_connection():
                    log.info(f"Successfully initialized {provider} provider")
                    return instance
                else:
                    log.warning(f"{provider} provider failed connection test, trying next provider")
                    continue
            else:
                return instance

        except Exception as e:
            log.warning(f"Failed to initialize {provider} provider: {e}")
            if not config.enable_fallback:
                raise
            continue

    raise ValueError(
        "No LLM provider available. Please configure at least one provider:\n"
        "- Set OPENAI_API_KEY for OpenAI\n"
        "- Set ANTHROPIC_API_KEY for Anthropic\n"
        "- Ensure Ollama is running at OLLAMA_BASE_URL"
    )


def _create_provider(provider_name: str, config: ProviderConfig, **kwargs) -> BaseLLMProvider:
    """
    Create a specific provider instance

    Args:
        provider_name: Name of the provider ('openai', 'anthropic', 'ollama')
        config: ProviderConfig instance
        **kwargs: Additional provider-specific configuration

    Returns:
        Configured provider instance

    Raises:
        ValueError: If provider name is invalid or configuration is missing
    """
    provider_name = provider_name.lower().strip()

    # Merge config with kwargs
    merged_kwargs = {
        'timeout': config.timeout,
        'max_retries': config.max_retries,
        **kwargs
    }

    if provider_name == 'openai':
        if not config.openai_api_key:
            raise ValueError("OpenAI API key not configured. Set OPENAI_API_KEY environment variable.")

        return OpenAIProvider(
            api_key=config.openai_api_key,
            model=config.openai_model,
            embedding_model=config.openai_embedding_model,
            **merged_kwargs
        )

    elif provider_name == 'anthropic':
        if not config.anthropic_api_key:
            raise ValueError("Anthropic API key not configured. Set ANTHROPIC_API_KEY environment variable.")

        return AnthropicProvider(
            api_key=config.anthropic_api_key,
            model=config.anthropic_model,
            **merged_kwargs
        )

    elif provider_name == 'ollama':
        return OllamaProvider(
            base_url=config.ollama_base_url,
            model=config.ollama_model,
            embedding_model=config.ollama_embedding_model,
            **merged_kwargs
        )

    else:
        raise ValueError(f"Unknown provider: {provider_name}. Choose from: openai, anthropic, ollama")


def list_available_providers(config: Optional[ProviderConfig] = None) -> Dict[str, bool]:
    """
    Check which providers are available based on configuration

    Args:
        config: ProviderConfig instance (will create default if not provided)

    Returns:
        Dictionary mapping provider names to availability status
    """
    if config is None:
        config = ProviderConfig()

    availability = {}

    # Check OpenAI
    availability['openai'] = bool(config.openai_api_key)

    # Check Anthropic
    availability['anthropic'] = bool(config.anthropic_api_key)

    # Check Ollama (always potentially available if endpoint is reachable)
    try:
        ollama = OllamaProvider(base_url=config.ollama_base_url, model=config.ollama_model)
        availability['ollama'] = ollama.test_connection()
    except Exception:
        availability['ollama'] = False

    return availability
