"""Ollama (local) provider — uses urllib from stdlib, no extra SDK needed."""
import json as _json
import logging
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from backend.app.services.providers.base import AIProvider

logger = logging.getLogger(__name__)


class OllamaProvider(AIProvider):
    name = "ollama"
    display_name = "Ollama (Local)"

    def __init__(self, base_url: str = "http://localhost:11434",
                 model_fast: str = "llama3.2",
                 model_quality: str = "llama3.1:70b"):
        self.base_url = base_url.rstrip("/")
        self.model_fast = model_fast
        self.model_quality = model_quality

    def is_available(self) -> bool:
        try:
            req = Request(f"{self.base_url}/api/tags")
            with urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def call(self, prompt: str, system: str = "", model: str | None = None,
             max_tokens: int = 1024, temperature: float = 0.0) -> Optional[str]:
        model = model or self.model_fast
        try:
            payload = {
                "model": model,
                "messages": [],
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature,
                },
            }
            if system:
                payload["messages"].append({"role": "system", "content": system})
            payload["messages"].append({"role": "user", "content": prompt})

            data = _json.dumps(payload).encode("utf-8")
            req = Request(
                f"{self.base_url}/api/chat",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=120) as resp:
                body = _json.loads(resp.read().decode("utf-8"))
                return body["message"]["content"]
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            return None
