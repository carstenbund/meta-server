# LLM Provider Abstraction Layer

This module provides a unified interface for interacting with multiple LLM providers (OpenAI, Anthropic, Ollama) for document indexing and analysis.

## Features

- **Multi-Provider Support**: Switch between OpenAI, Anthropic, and Ollama
- **Token-Key Based Selection**: Automatically selects provider based on available API keys
- **Fallback Support**: Gracefully falls back to alternative providers if primary fails
- **Unified Interface**: Common API across all providers
- **Embeddings Support**: Generate embeddings with OpenAI or Ollama
- **Configuration-Driven**: Flexible configuration via environment variables

## Architecture

```
llm_providers/
├── __init__.py           # Package initialization
├── base.py              # Abstract base class
├── openai_provider.py   # OpenAI implementation
├── anthropic_provider.py # Anthropic implementation
├── ollama_provider.py   # Ollama implementation
└── factory.py           # Provider factory with auto-selection
```

## Providers

### OpenAI
- **Models**: GPT-4o-mini (default), GPT-4, GPT-3.5
- **Embeddings**: text-embedding-3-small (default)
- **Requires**: API key from https://platform.openai.com/
- **Best for**: High-quality inference and embeddings

### Anthropic (Claude)
- **Models**: Claude 3.5 Haiku (default), Claude 3 Opus, Claude 3 Sonnet
- **Embeddings**: Not supported (use OpenAI or Ollama)
- **Requires**: API key from https://console.anthropic.com/
- **Best for**: High-quality inference with strong reasoning

### Ollama
- **Models**: Llama 3.2 (default), Mistral, many others
- **Embeddings**: nomic-embed-text (default)
- **Requires**: Local Ollama installation from https://ollama.ai/
- **Best for**: Local/offline processing, privacy-sensitive data

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Provider

Copy the example environment file and configure your preferred provider:

```bash
cp .env.example .env
# Edit .env with your API keys
```

For OpenAI:
```bash
export OPENAI_API_KEY="your-api-key-here"
```

For Anthropic:
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

For Ollama (local):
```bash
# Install Ollama from https://ollama.ai/
ollama pull llama3.2
ollama pull nomic-embed-text
ollama serve
```

### 3. Use in Code

```python
from llm_providers import get_llm_provider

# Auto-select provider based on configuration
provider = get_llm_provider()

# Or specify explicitly
provider = get_llm_provider(provider_name='openai')

# Infer category, keywords, and summary
response = provider.infer_category_and_keywords(
    content="Your document content here",
    language="en",
    file_path="/path/to/document.pdf"
)

print(f"Category: {response.category}")
print(f"Keywords: {response.keywords}")
print(f"Summary: {response.summary}")

# Generate embeddings (OpenAI or Ollama only)
embedding_response = provider.generate_embedding("Content to embed")
print(f"Embedding dimensions: {len(embedding_response.embedding)}")

# Generic chat completion
messages = [
    {"role": "user", "content": "Hello!"}
]
response_text = provider.chat_completion(messages)
print(response_text)
```

## Running the Index Worker

The modernized index worker uses the LLM provider abstraction:

```bash
# Using default provider (auto-selected)
python indexer/index_worker.py

# Using specific provider
LLM_PROVIDER=openai python indexer/index_worker.py

# With embeddings enabled
ENABLE_EMBEDDINGS=true python indexer/index_worker.py

# Using Ollama (local)
LLM_PROVIDER=ollama python indexer/index_worker.py
```

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | Explicit provider selection | Auto-detect |
| `LLM_PROVIDER_PREFERENCE` | Fallback order | `openai,anthropic,ollama` |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `OPENAI_MODEL` | OpenAI model name | `gpt-4o-mini` |
| `OPENAI_EMBEDDING_MODEL` | OpenAI embedding model | `text-embedding-3-small` |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `ANTHROPIC_MODEL` | Anthropic model name | `claude-3-5-haiku-20241022` |
| `OLLAMA_BASE_URL` | Ollama server URL | `http://localhost:11434` |
| `OLLAMA_MODEL` | Ollama model name | `llama3.2` |
| `OLLAMA_EMBEDDING_MODEL` | Ollama embedding model | `nomic-embed-text` |
| `LLM_TIMEOUT` | Request timeout (seconds) | `60` |
| `LLM_MAX_RETRIES` | Max retry attempts | `3` |
| `ENABLE_EMBEDDINGS` | Enable embedding generation | `false` |

## Provider Selection Logic

The factory uses the following logic to select a provider:

1. If `LLM_PROVIDER` is set explicitly, use that provider
2. Otherwise, check providers in `LLM_PROVIDER_PREFERENCE` order
3. For each provider, verify:
   - API keys are configured (OpenAI, Anthropic)
   - Service is reachable (Ollama)
   - Connection test succeeds
4. Use the first working provider
5. Fall back to next provider if current one fails

## API Reference

### BaseLLMProvider

Abstract base class that all providers implement.

#### Methods

- `infer_category_and_keywords(content, language, file_path)` → `LLMResponse`
  - Analyze content and extract category, keywords, and summary

- `generate_embedding(content)` → `EmbeddingResponse`
  - Generate embedding vector for content

- `chat_completion(messages, temperature, max_tokens)` → `str`
  - Generic chat completion

- `test_connection()` → `bool`
  - Test if provider is available

### Response Types

#### LLMResponse
```python
@dataclass
class LLMResponse:
    category: Optional[str]
    keywords: Optional[str]
    summary: Optional[str]
    raw_response: Optional[str]
    metadata: Optional[Dict[str, Any]]
```

#### EmbeddingResponse
```python
@dataclass
class EmbeddingResponse:
    embedding: List[float]
    model: str
    metadata: Optional[Dict[str, Any]]
```

## Migration from Old System

The old `inference_server.py` can be replaced with this abstraction:

### Before (Old System)
```python
response = requests.post(INFERENCE_URL, json={
    "content": content,
    "language": lang
})
result = response.json()
```

### After (New System)
```python
from llm_providers import get_llm_provider

provider = get_llm_provider()
response = provider.infer_category_and_keywords(
    content=content,
    language=lang
)
```

## Troubleshooting

### OpenAI Connection Fails
- Verify API key is correct: `echo $OPENAI_API_KEY`
- Check API quota and billing: https://platform.openai.com/usage
- Ensure network connectivity to api.openai.com

### Anthropic Connection Fails
- Verify API key is correct: `echo $ANTHROPIC_API_KEY`
- Check API quota: https://console.anthropic.com/
- Ensure network connectivity to api.anthropic.com

### Ollama Connection Fails
- Verify Ollama is running: `ollama list`
- Check server is accessible: `curl http://localhost:11434/api/tags`
- Pull required models:
  ```bash
  ollama pull llama3.2
  ollama pull nomic-embed-text
  ```

### "No LLM provider available" Error
- At least one provider must be configured
- Set API key environment variable or run Ollama locally
- Check provider configuration with:
  ```python
  from llm_providers.factory import list_available_providers
  print(list_available_providers())
  ```

## Performance Considerations

- **OpenAI**: Fast, cloud-based, metered billing
- **Anthropic**: Fast, cloud-based, metered billing
- **Ollama**: Slower (depends on hardware), local, free

For production use:
- Use OpenAI/Anthropic for speed and quality
- Use Ollama for sensitive data or offline scenarios
- Enable fallback for high availability
- Consider rate limits and adjust `NUM_WORKERS` accordingly

## Security Notes

- **API Keys**: Never commit API keys to version control
- **Sensitive Data**: Use Ollama for PII or confidential documents
- **Local Processing**: Ollama processes everything locally
- **Cloud Processing**: OpenAI/Anthropic send data to their APIs

## Future Enhancements

- [ ] Add support for Azure OpenAI
- [ ] Add support for Google Gemini
- [ ] Implement request queuing and rate limiting
- [ ] Add response caching
- [ ] Structured output validation
- [ ] Batch processing optimization
- [ ] Vector database integration for embeddings
