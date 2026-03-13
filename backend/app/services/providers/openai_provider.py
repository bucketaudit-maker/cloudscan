"""OpenAI GPT provider."""
import logging
from typing import Optional

from backend.app.services.providers.base import AIProvider

logger = logging.getLogger(__name__)


class OpenAIProvider(AIProvider):
    name = "openai"
    display_name = "OpenAI GPT"

    def __init__(self, api_key: str, model_fast: str = "gpt-4o-mini",
                 model_quality: str = "gpt-4o"):
        self.api_key = api_key
        self.model_fast = model_fast
        self.model_quality = model_quality
        self._client = None

    def _get_client(self):
        if not self.api_key:
            return None
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key)
            except ImportError:
                logger.error("openai package not installed — pip install openai")
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
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return None
