"""Google Gemini provider."""
import logging
from typing import Optional

from backend.app.services.providers.base import AIProvider

logger = logging.getLogger(__name__)


class GoogleProvider(AIProvider):
    name = "google"
    display_name = "Google Gemini"

    def __init__(self, api_key: str, model_fast: str = "gemini-2.0-flash",
                 model_quality: str = "gemini-2.5-pro"):
        self.api_key = api_key
        self.model_fast = model_fast
        self.model_quality = model_quality
        self._configured = False

    def _ensure_configured(self) -> bool:
        if not self.api_key:
            return False
        if not self._configured:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self._configured = True
            except ImportError:
                logger.error("google-generativeai package not installed — pip install google-generativeai")
                return False
        return True

    def is_available(self) -> bool:
        return self._ensure_configured()

    def call(self, prompt: str, system: str = "", model: str | None = None,
             max_tokens: int = 1024, temperature: float = 0.0) -> Optional[str]:
        if not self._ensure_configured():
            return None
        model_name = model or self.model_fast
        try:
            import google.generativeai as genai
            gen_config = genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            )
            model_obj = genai.GenerativeModel(
                model_name=model_name,
                system_instruction=system if system else None,
                generation_config=gen_config,
            )
            response = model_obj.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Google Gemini API error: {e}")
            return None
