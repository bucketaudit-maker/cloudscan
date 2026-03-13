"""
Multi-provider AI abstraction layer.

Supports: Anthropic Claude, OpenAI GPT, Google Gemini, Ollama (local).
"""
from backend.app.services.providers.registry import (
    get_provider,
    set_provider,
    list_providers,
    get_active_provider_name,
    init_default_provider,
)

__all__ = [
    "get_provider",
    "set_provider",
    "list_providers",
    "get_active_provider_name",
    "init_default_provider",
]
