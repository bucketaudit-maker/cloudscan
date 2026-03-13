"""Abstract base class for AI providers."""
from abc import ABC, abstractmethod
from typing import Optional


class AIProvider(ABC):
    """Base class all AI providers must implement."""

    name: str = ""            # e.g., "anthropic", "openai", "google", "ollama"
    display_name: str = ""    # e.g., "Anthropic Claude", "OpenAI GPT"
    model_fast: str = ""      # Model for fast operations (classify, search, keywords)
    model_quality: str = ""   # Model for quality operations (reports)

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if provider is configured and reachable."""
        ...

    @abstractmethod
    def call(self, prompt: str, system: str = "", model: str | None = None,
             max_tokens: int = 1024, temperature: float = 0.0) -> Optional[str]:
        """Send a prompt to the LLM. Returns response text or None on failure."""
        ...
