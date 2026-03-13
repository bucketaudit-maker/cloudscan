"""Provider registry — manages available AI providers and active selection."""
import logging

logger = logging.getLogger(__name__)

_providers: dict = {}           # name -> AIProvider instance
_active_provider_name: str = "" # currently selected provider
_initialized: bool = False


def _init_providers():
    """Lazy-initialize all providers from config. Called once."""
    global _providers, _initialized
    if _initialized:
        return
    _initialized = True

    from backend.app.config import settings
    from backend.app.services.providers.anthropic_provider import AnthropicProvider
    from backend.app.services.providers.openai_provider import OpenAIProvider
    from backend.app.services.providers.google_provider import GoogleProvider
    from backend.app.services.providers.ollama_provider import OllamaProvider

    if settings.ANTHROPIC_API_KEY:
        _providers["anthropic"] = AnthropicProvider(
            api_key=settings.ANTHROPIC_API_KEY,
            model_fast=settings.AI_MODEL_FAST,
            model_quality=settings.AI_MODEL_QUALITY,
        )

    if settings.OPENAI_API_KEY:
        _providers["openai"] = OpenAIProvider(
            api_key=settings.OPENAI_API_KEY,
            model_fast=settings.OPENAI_MODEL_FAST,
            model_quality=settings.OPENAI_MODEL_QUALITY,
        )

    if settings.GOOGLE_API_KEY:
        _providers["google"] = GoogleProvider(
            api_key=settings.GOOGLE_API_KEY,
            model_fast=settings.GOOGLE_MODEL_FAST,
            model_quality=settings.GOOGLE_MODEL_QUALITY,
        )

    if settings.OLLAMA_BASE_URL:
        _providers["ollama"] = OllamaProvider(
            base_url=settings.OLLAMA_BASE_URL,
            model_fast=settings.OLLAMA_MODEL_FAST,
            model_quality=settings.OLLAMA_MODEL_QUALITY,
        )

    logger.info(f"AI providers configured: {list(_providers.keys()) or 'none'}")


def get_provider(name: str = None):
    """Get a provider by name, or the active provider if name is None."""
    _init_providers()
    if name:
        return _providers.get(name)
    return _providers.get(_active_provider_name)


def set_provider(name: str) -> bool:
    """Set the active provider. Returns True on success."""
    global _active_provider_name
    _init_providers()
    if name not in _providers:
        return False
    p = _providers[name]
    if not p.is_available():
        return False
    _active_provider_name = name
    logger.info(f"AI provider switched to: {name} ({p.display_name})")
    return True


def get_active_provider_name() -> str:
    """Return the name of the currently active provider."""
    _init_providers()
    return _active_provider_name


def list_providers() -> list[dict]:
    """Return info about all configured providers."""
    _init_providers()
    result = []
    for name, p in _providers.items():
        result.append({
            "name": p.name,
            "display_name": p.display_name,
            "model_fast": p.model_fast,
            "model_quality": p.model_quality,
            "available": p.is_available(),
            "active": name == _active_provider_name,
        })
    return result


def init_default_provider():
    """Set the default provider from AI_PROVIDER env var. Called at startup."""
    global _active_provider_name
    _init_providers()

    from backend.app.config import settings
    preferred = settings.AI_PROVIDER

    if preferred and preferred in _providers:
        _active_provider_name = preferred
        logger.info(f"Default AI provider: {preferred} ({_providers[preferred].display_name})")
    elif _providers:
        # Auto-select first available provider
        for name, p in _providers.items():
            if p.is_available():
                _active_provider_name = name
                logger.info(f"Auto-selected AI provider: {name} ({p.display_name})")
                break

    if not _active_provider_name:
        logger.warning("No AI providers configured or available")
