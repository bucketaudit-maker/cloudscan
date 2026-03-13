"""Anthropic Claude provider."""
import logging
from typing import Optional

from backend.app.services.providers.base import AIProvider

logger = logging.getLogger(__name__)


class AnthropicProvider(AIProvider):
    name = "anthropic"
    display_name = "Anthropic Claude"

    def __init__(self, api_key: str, model_fast: str, model_quality: str):
        self.api_key = api_key
        self.model_fast = model_fast
        self.model_quality = model_quality
        self._client = None

    def _get_client(self):
        if not self.api_key:
            return None
        if self._client is None:
            try:
                from anthropic import Anthropic
                self._client = Anthropic(api_key=self.api_key)
            except ImportError:
                logger.error("anthropic package not installed — pip install anthropic")
                return None
        return self._client

    def is_available(self) -> bool:
        return self._get_client() is not None

    def call(self, prompt: str, system: str = "", model: str | None = None,
             max_tokens: int = 1024, temperature: float = 0.0) -> Optional[str]:
        client = self._get_client()
        if not client:
            return None
        model = model or self.model_fast
        try:
            kwargs = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
            }
            if system:
                kwargs["system"] = system
            response = client.messages.create(**kwargs)
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return None
