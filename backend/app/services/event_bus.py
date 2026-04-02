"""
Event Bus — Centralized event dispatcher.

Fans out events to notification_service, webhook_service, and integration_service.
Handlers run in daemon threads to avoid blocking the caller.
"""
import logging
import threading
from datetime import datetime, timezone
from typing import Callable

logger = logging.getLogger(__name__)

# Supported event types
EVENT_TYPES = {
    "bucket_found",
    "status_change",
    "risk_threshold",
    "scan_complete",
    "sensitive_file",
    "new_files",
}

# Registry: event_type -> list of handler callables
_handlers: dict[str, list[Callable]] = {}
_lock = threading.Lock()


def subscribe(event_type: str, handler: Callable):
    """Register a handler for an event type."""
    with _lock:
        _handlers.setdefault(event_type, []).append(handler)
    logger.debug(f"[EventBus] Subscribed {handler.__name__} to '{event_type}'")


def unsubscribe(event_type: str, handler: Callable):
    """Remove a handler from an event type."""
    with _lock:
        handlers = _handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)


def emit(event_type: str, data: dict = None):
    """
    Dispatch an event to all registered handlers.

    Each handler runs in a daemon thread so the caller is never blocked.
    """
    if event_type not in EVENT_TYPES:
        logger.warning(f"[EventBus] Unknown event type: {event_type}")

    payload = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
    }

    with _lock:
        handlers = list(_handlers.get(event_type, []))

    if not handlers:
        logger.debug(f"[EventBus] No handlers for '{event_type}'")
        return

    for handler in handlers:
        t = threading.Thread(
            target=_safe_call, args=(handler, payload),
            daemon=True, name=f"event-{event_type}-{handler.__name__}",
        )
        t.start()


def _safe_call(handler: Callable, payload: dict):
    """Call a handler, catching and logging any exceptions."""
    try:
        handler(payload)
    except Exception as e:
        logger.error(f"[EventBus] Handler {handler.__name__} failed: {e}")


def register_default_handlers():
    """Wire up the default notification, webhook, and integration handlers."""
    try:
        from backend.app.services.notification_service import notify_user

        def _on_bucket_found(payload):
            data = payload.get("data", {})
            user_id = data.get("user_id")
            if not user_id:
                return
            notify_user(
                user_id=user_id, ntype="alert",
                title=f"Bucket discovered: {data.get('bucket_name', 'unknown')}",
                body=f"Status: {data.get('status', 'unknown')} | Provider: {data.get('provider', 'unknown')}",
                severity=data.get("severity", "medium"),
            )

        subscribe("bucket_found", _on_bucket_found)
    except ImportError:
        logger.debug("[EventBus] notification_service not available")

    try:
        from backend.app.services.webhook_service import dispatch_alert

        def _on_any_webhook(payload):
            data = payload.get("data", {})
            user_id = data.get("user_id")
            if not user_id:
                return
            alert = {
                "title": f"CloudScan: {payload['event']}",
                "severity": data.get("severity", "medium"),
                "description": str(data),
            }
            dispatch_alert(alert, user_id)

        for evt in EVENT_TYPES:
            subscribe(evt, _on_any_webhook)
    except ImportError:
        logger.debug("[EventBus] webhook_service not available")

    try:
        from backend.app.services.integration_service import dispatch_to_integrations

        def _on_any_integration(payload):
            data = payload.get("data", {})
            user_id = data.get("user_id")
            if not user_id:
                return
            dispatch_to_integrations(user_id, payload)

        for evt in EVENT_TYPES:
            subscribe(evt, _on_any_integration)
    except (ImportError, AttributeError):
        logger.debug("[EventBus] integration_service dispatch not available")

    logger.info("[EventBus] Default handlers registered")
