"""
Notification dispatch service.

Creates in-app notifications and dispatches to external channels (Slack)
based on user preferences. Fires external notifications in daemon threads.
"""
import json
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime

from backend.app.models.database import (
    NotificationStore, NotificationPrefStore, SlackConfigStore,
)

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def notify_user(user_id: int, ntype: str, title: str, body: str = None,
                link: str = None, metadata: dict = None, severity: str = "medium"):
    """
    Send a notification to a user.

    Always creates an in-app notification. Checks user prefs for Slack
    and dispatches if enabled and severity meets threshold.
    """
    # 1. Always create in-app notification
    try:
        notif = NotificationStore.create(
            user_id=user_id, type=ntype, title=title,
            body=body, link=link, metadata=metadata,
        )
        logger.info(f"[Notify] In-app notification created for user {user_id}: {title}")
    except Exception as e:
        logger.error(f"[Notify] Failed to create in-app notification: {e}")
        notif = {}

    # 2. Check external channel preferences
    try:
        prefs = NotificationPrefStore.get_for_user(user_id)
    except Exception as e:
        logger.error(f"[Notify] Failed to fetch prefs for user {user_id}: {e}")
        return notif

    for pref in prefs:
        if not pref.get("enabled"):
            continue
        min_sev = pref.get("min_severity", "medium")
        if SEVERITY_LEVELS.get(severity, 0) < SEVERITY_LEVELS.get(min_sev, 0):
            continue

        channel = pref.get("channel")
        if channel == "slack":
            _dispatch_slack(user_id, title, body, severity, link)

    return notif


def _dispatch_slack(user_id: int, title: str, body: str, severity: str, link: str = None):
    """Dispatch notification to Slack in a background thread."""
    try:
        configs = SlackConfigStore.get_for_user(user_id)
        if not configs:
            return
        # get_for_user returns a list; send to each active config
        for config in (configs if isinstance(configs, list) else [configs]):
            t = threading.Thread(
                target=_send_slack_message,
                args=(config, title, body, severity, link),
                daemon=True,
            )
            t.start()
    except Exception as e:
        logger.error(f"[Notify] Slack dispatch error for user {user_id}: {e}")


def _send_slack_message(config: dict, title: str, body: str, severity: str, link: str = None):
    """POST Slack Block Kit message to webhook URL."""
    color_map = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#17a2b8", "info": "#6c757d"}
    color = color_map.get(severity, "#6c757d")
    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity, "⚪")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} CloudScan Alert", "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Title:*\n{title}"},
            ]
        },
    ]
    if body:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": body[:2000]}
        })
    if link:
        blocks.append({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "View Details"},
                "url": link,
            }]
        })

    payload = json.dumps({
        "text": f"{emoji} [{severity.upper()}] {title}",
        "blocks": blocks,
        "attachments": [{"color": color, "blocks": []}],
    }).encode("utf-8")

    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return

    req = urllib.request.Request(
        webhook_url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                logger.info(f"[Notify] Slack message delivered to {config.get('channel_name', 'webhook')}")
            else:
                logger.warning(f"[Notify] Slack returned {resp.status}")
    except Exception as e:
        logger.error(f"[Notify] Slack delivery failed: {e}")
