"""
Webhook dispatch service.

Sends alert payloads to registered webhook URLs with optional HMAC-SHA256 signing.
Fires webhooks in daemon threads to avoid blocking alert creation.
"""
import hashlib
import hmac
import json
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime

from backend.app.models.database import WebhookStore

logger = logging.getLogger(__name__)


def dispatch_alert(alert: dict, user_id: int):
    """Dispatch an alert to all active webhooks for the user whose event_types match."""
    try:
        webhooks = WebhookStore.get_active_for_user(user_id)
    except Exception as e:
        logger.error(f"[Webhook] Failed to fetch webhooks for user {user_id}: {e}")
        return

    severity = alert.get("severity", "info")
    for wh in webhooks:
        try:
            event_types = json.loads(wh["event_types"]) if isinstance(wh["event_types"], str) else wh["event_types"]
        except (json.JSONDecodeError, TypeError):
            event_types = ["critical", "high"]
        if severity not in event_types:
            continue
        t = threading.Thread(target=_send_webhook, args=(wh, alert), daemon=True)
        t.start()


def _send_webhook(webhook: dict, payload: dict):
    """POST JSON payload to webhook URL with optional HMAC signing."""
    body = json.dumps({
        "event": "alert",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "alert": payload,
    }).encode("utf-8")

    headers = {"Content-Type": "application/json", "X-CloudScan-Event": "alert"}
    if webhook.get("secret"):
        sig = hmac.new(webhook["secret"].encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-CloudScan-Signature"] = sig

    req = urllib.request.Request(webhook["url"], data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                WebhookStore.mark_triggered(webhook["id"])
                WebhookStore.reset_failure(webhook["id"])
                logger.info(f"[Webhook] Delivered to {webhook['name']} ({webhook['url']})")
            else:
                WebhookStore.increment_failure(webhook["id"])
                logger.warning(f"[Webhook] {webhook['name']} returned {resp.status}")
    except Exception as e:
        WebhookStore.increment_failure(webhook["id"])
        logger.error(f"[Webhook] Failed to deliver to {webhook['name']}: {e}")


def send_test(webhook: dict) -> dict:
    """Send a test payload to a webhook, return success/error."""
    body = json.dumps({
        "event": "test",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "alert": {
            "id": 0,
            "alert_type": "test",
            "severity": "info",
            "title": "CloudScan Webhook Test",
            "description": "This is a test alert from CloudScan.",
        },
    }).encode("utf-8")

    headers = {"Content-Type": "application/json", "X-CloudScan-Event": "test"}
    if webhook.get("secret"):
        sig = hmac.new(webhook["secret"].encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-CloudScan-Signature"] = sig

    req = urllib.request.Request(webhook["url"], data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"success": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
