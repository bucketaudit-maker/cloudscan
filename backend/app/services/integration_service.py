"""
Integration dispatch service — Slack and Jira.

Provides helpers to send alerts/messages via configured integrations.
All external calls run in daemon threads to avoid blocking the request.
"""
import json
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime

from backend.app.models.database import IntegrationStore

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# SLACK
# ═══════════════════════════════════════════════════════════════════

def send_slack_alert(config: dict, alert: dict) -> dict:
    """
    Send an alert payload to a Slack webhook.

    config: integration config dict with 'webhook_url'
    alert: alert dict with title, severity, description, etc.
    Returns: {"success": True/False, "error": ...}
    """
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return {"success": False, "error": "No webhook_url configured"}

    severity = alert.get("severity", "medium")
    title = alert.get("title", "CloudScan Alert")
    description = alert.get("description", "")
    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(severity, "⚪")

    payload = json.dumps({
        "text": f"{emoji} [{severity.upper()}] {title}",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} CloudScan Alert", "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Type:* {alert.get('alert_type', 'alert')}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{title}*\n{description[:2000]}"}
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Sent by CloudScan at {datetime.utcnow().isoformat()}Z"}
                ]
            },
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        webhook_url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"success": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def send_slack_alert_async(config: dict, alert: dict):
    """Fire-and-forget Slack alert in a daemon thread."""
    t = threading.Thread(target=send_slack_alert, args=(config, alert), daemon=True)
    t.start()


# ═══════════════════════════════════════════════════════════════════
# JIRA
# ═══════════════════════════════════════════════════════════════════

def create_jira_issue(config: dict, alert: dict) -> dict:
    """
    Create a Jira issue from an alert.

    config: integration config dict with 'base_url', 'email', 'api_token', 'project_key'
    alert: alert dict with title, description, severity
    Returns: {"success": True, "issue_key": "PROJ-123", "url": "..."} or {"success": False, "error": ...}
    """
    base_url = config.get("base_url", "").rstrip("/")
    email = config.get("email", "")
    api_token = config.get("api_token", "")
    project_key = config.get("project_key", "")

    if not all([base_url, email, api_token, project_key]):
        return {"success": False, "error": "Incomplete Jira configuration (need base_url, email, api_token, project_key)"}

    severity = alert.get("severity", "medium")
    priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}
    priority = priority_map.get(severity, "Medium")

    issue_data = {
        "fields": {
            "project": {"key": project_key},
            "summary": alert.get("title", "CloudScan Security Alert")[:255],
            "description": {
                "type": "doc", "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": alert.get("description", "Security issue detected by CloudScan")}]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": f"Severity: {severity.upper()}", "marks": [{"type": "strong"}]},
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": f"Alert Type: {alert.get('alert_type', 'unknown')}"},
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": f"Created by CloudScan at {datetime.utcnow().isoformat()}Z"},
                        ]
                    },
                ]
            },
            "issuetype": {"name": config.get("issue_type", "Bug")},
            "priority": {"name": priority},
            "labels": ["cloudscan", f"severity-{severity}"],
        }
    }

    payload = json.dumps(issue_data).encode("utf-8")

    # Basic auth: email:api_token base64 encoded
    import base64
    auth = base64.b64encode(f"{email}:{api_token}".encode()).decode()

    req = urllib.request.Request(
        f"{base_url}/rest/api/3/issue",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            issue_key = resp_data.get("key", "")
            return {
                "success": True,
                "issue_key": issue_key,
                "url": f"{base_url}/browse/{issue_key}",
                "id": resp_data.get("id"),
            }
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")[:500]
        except Exception:
            pass
        return {"success": False, "error": f"HTTP {e.code}: {error_body}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════
# TEST / GENERIC
# ═══════════════════════════════════════════════════════════════════

def test_integration(integration: dict) -> dict:
    """
    Test an integration by sending a test payload.
    integration: dict from IntegrationStore with 'type' and 'config'
    """
    int_type = integration.get("type")
    try:
        config = json.loads(integration["config"]) if isinstance(integration["config"], str) else integration["config"]
    except (json.JSONDecodeError, TypeError):
        return {"success": False, "error": "Invalid integration config"}

    test_alert = {
        "id": 0,
        "alert_type": "test",
        "severity": "info",
        "title": "CloudScan Integration Test",
        "description": "This is a test alert from CloudScan to verify your integration is working.",
    }

    if int_type == "slack":
        return send_slack_alert(config, test_alert)
    elif int_type == "jira":
        return create_jira_issue(config, test_alert)
    else:
        return {"success": False, "error": f"Unknown integration type: {int_type}"}


def dispatch_to_integrations(user_id: int, alert: dict):
    """Send alert to all active integrations for a user (async)."""
    try:
        slack_integrations = IntegrationStore.get_active_by_type(user_id, "slack")
        for integration in slack_integrations:
            try:
                config = json.loads(integration["config"]) if isinstance(integration["config"], str) else integration["config"]
                send_slack_alert_async(config, alert)
            except Exception as e:
                logger.error(f"[Integration] Slack dispatch error: {e}")
    except Exception as e:
        logger.error(f"[Integration] Failed to fetch integrations for user {user_id}: {e}")
