"""
Feature Routes — Sprint 7: All 20 new features API endpoints.

Registered as a sub-blueprint of the main API blueprint.
"""
import json
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, g

from backend.app.models.database import get_db, BucketStore, FileStore
from backend.app.utils.auth import auth_required
from backend.app.services.features import (
    # Feature 1: Subdomain discovery
    generate_subdomain_names,
    # Feature 2: GitHub leak scanning
    extract_bucket_refs_from_text,
    # Feature 3: Wildcard/regex search
    search_buckets_regex,
    # Feature 5: Sensitive data classification
    deep_classify_files, SENSITIVE_PATTERNS,
    # Feature 6: Compliance mapping
    map_findings_to_compliance, COMPLIANCE_CONTROL_MAP,
    # Feature 7: Exposure severity scoring
    calculate_exposure_score,
    # Feature 8: Breach timeline
    calculate_breach_timeline,
    # Feature 9: Industry/sector view
    get_industry_breakdown, classify_company_industry,
    # Feature 11: Trend analytics
    get_trend_data,
    # Feature 12: Attack surface mapping
    get_attack_surface,
    # Feature 15: SIEM export
    export_siem_events,
    # Feature 19: Takedown assistance
    generate_takedown_guide, PROVIDER_ABUSE_CONTACTS,
    # Feature 20: Competitor intelligence
    get_competitor_benchmark,
)

logger = logging.getLogger(__name__)

features_api = Blueprint("features_api", __name__)


# ═══════════════════════════════════════════════════════════════════
# Feature 1: Subdomain-based Bucket Discovery
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/discovery/subdomains", methods=["POST"])
@auth_required
def generate_subdomain_buckets():
    """Generate bucket names from domain/subdomain patterns."""
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    names = generate_subdomain_names(domain)
    return jsonify({"domain": domain, "bucket_names": names, "count": len(names)})


# ═══════════════════════════════════════════════════════════════════
# Feature 2: GitHub Leak Scanning
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/discovery/extract-refs", methods=["POST"])
@auth_required
def extract_bucket_references():
    """Extract bucket references from pasted code/text."""
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "text is required"}), 400
    refs = extract_bucket_refs_from_text(text)
    return jsonify({"references": refs, "count": len(refs)})


# ═══════════════════════════════════════════════════════════════════
# Feature 3: Wildcard/Regex Bucket Search
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/buckets/search/pattern", methods=["GET"])
@auth_required
def pattern_search_buckets():
    """Search buckets using wildcard patterns (e.g., *-backup-*, prod-*)."""
    pattern = request.args.get("pattern", "")
    limit = min(int(request.args.get("limit", 100)), 500)
    if not pattern:
        return jsonify({"error": "pattern parameter is required"}), 400
    results = search_buckets_regex(pattern, limit)
    return jsonify({"pattern": pattern, "results": results, "count": len(results)})


# ═══════════════════════════════════════════════════════════════════
# Feature 4: Scheduled Re-scan with Change Detection
# (Uses existing scan_schedules + drift detection infrastructure)
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/discovery/rescan-changes", methods=["GET"])
@auth_required
def get_rescan_changes():
    """Get recent changes detected by scheduled re-scans."""
    from datetime import datetime, timezone, timedelta
    days = min(int(request.args.get("days", 7)), 90)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with get_db() as db:
        changes = db.execute("""
            SELECT sd.*, b.name as bucket_name, b.status, b.company_name,
                   p.display_name as provider_name
            FROM scan_diffs sd
            JOIN buckets b ON sd.bucket_id=b.id
            JOIN providers p ON b.provider_id=p.id
            WHERE sd.created_at >= %s
            ORDER BY sd.created_at DESC LIMIT 200
        """, (cutoff,)).fetchall()
    return jsonify({
        "period_days": days,
        "changes": [dict(r) for r in changes],
        "count": len(changes),
    })


# ═══════════════════════════════════════════════════════════════════
# Feature 5: Sensitive Data Classification (deep scan)
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/sensitive/scan/<int:bucket_id>", methods=["POST"])
@auth_required
def scan_sensitive_data(bucket_id):
    """Run deep sensitive data classification on a bucket's files."""
    with get_db() as db:
        files = db.execute(
            "SELECT id, filepath, filename, extension, size_bytes FROM files WHERE bucket_id=%s",
            (bucket_id,)
        ).fetchall()
    if not files:
        return jsonify({"findings": [], "count": 0, "message": "No files to scan"})

    file_dicts = [dict(f) for f in files]
    findings = deep_classify_files(file_dicts)

    # Store findings
    with get_db() as db:
        for f in findings:
            db.execute("""
                INSERT INTO sensitive_findings (bucket_id, file_id, filepath, category, severity, compliance_controls)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (bucket_id, filepath) DO UPDATE SET
                    category=EXCLUDED.category, severity=EXCLUDED.severity,
                    compliance_controls=EXCLUDED.compliance_controls, scanned_at=CURRENT_TIMESTAMP
            """, (bucket_id, f.get("file_id"), f["filepath"], f["category"],
                  f["severity"], json.dumps(f.get("compliance_controls", []))))

    return jsonify({"findings": findings, "count": len(findings)})


@features_api.route("/sensitive/findings", methods=["GET"])
@auth_required
def list_sensitive_findings():
    """List sensitive data findings, optionally filtered by bucket."""
    bucket_id = request.args.get("bucket_id")
    severity = request.args.get("severity")
    limit = min(int(request.args.get("limit", 100)), 500)

    conditions = []
    params = []
    if bucket_id:
        conditions.append("sf.bucket_id=%s")
        params.append(int(bucket_id))
    if severity:
        conditions.append("sf.severity=%s")
        params.append(severity)

    where = " AND ".join(conditions) if conditions else "1=1"
    params.append(limit)

    with get_db() as db:
        rows = db.execute(f"""
            SELECT sf.*, b.name as bucket_name, b.status, p.display_name as provider_name
            FROM sensitive_findings sf
            JOIN buckets b ON sf.bucket_id=b.id
            JOIN providers p ON b.provider_id=p.id
            WHERE {where}
            ORDER BY CASE sf.severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 ELSE 4 END, sf.scanned_at DESC
            LIMIT %s
        """, tuple(params)).fetchall()
    return jsonify({"findings": [dict(r) for r in rows], "count": len(rows)})


@features_api.route("/sensitive/summary", methods=["GET"])
@auth_required
def sensitive_summary():
    """Get summary of sensitive data findings."""
    with get_db() as db:
        by_severity = db.execute("""
            SELECT severity, COUNT(*) as count FROM sensitive_findings GROUP BY severity
        """).fetchall()
        by_category = db.execute("""
            SELECT category, COUNT(*) as count FROM sensitive_findings GROUP BY category ORDER BY count DESC
        """).fetchall()
        recent = db.execute("""
            SELECT sf.*, b.name as bucket_name FROM sensitive_findings sf
            JOIN buckets b ON sf.bucket_id=b.id
            ORDER BY sf.scanned_at DESC LIMIT 10
        """).fetchall()
    return jsonify({
        "by_severity": {r[0]: r[1] for r in by_severity},
        "by_category": {r[0]: r[1] for r in by_category},
        "recent_findings": [dict(r) for r in recent],
    })


# ═══════════════════════════════════════════════════════════════════
# Feature 6: Compliance Mapping
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/compliance/violations", methods=["GET"])
@auth_required
def get_compliance_violations():
    """Map sensitive findings to compliance control violations."""
    with get_db() as db:
        findings = db.execute("""
            SELECT filepath, category, severity, compliance_controls
            FROM sensitive_findings
        """).fetchall()

    finding_dicts = []
    for f in findings:
        row = dict(f)
        row["compliance_controls"] = json.loads(row.get("compliance_controls", "[]"))
        finding_dicts.append(row)

    violations = map_findings_to_compliance(finding_dicts)
    return jsonify({
        "violations": list(violations.values()),
        "total_controls_violated": len(violations),
        "frameworks_affected": list(set(v["framework"] for v in violations.values())),
    })


@features_api.route("/compliance/controls", methods=["GET"])
@auth_required
def list_compliance_controls():
    """List all known compliance controls."""
    return jsonify({"controls": COMPLIANCE_CONTROL_MAP})


# ═══════════════════════════════════════════════════════════════════
# Feature 7: Exposure Severity Scoring
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/exposure/<int:bucket_id>", methods=["GET"])
@auth_required
def get_exposure_score(bucket_id):
    """Get detailed exposure severity score for a bucket."""
    with get_db() as db:
        bucket = db.execute("SELECT * FROM buckets WHERE id=%s", (bucket_id,)).fetchone()
        if not bucket:
            return jsonify({"error": "Bucket not found"}), 404
        files = db.execute(
            "SELECT id, filepath, filename, extension, size_bytes FROM files WHERE bucket_id=%s",
            (bucket_id,)
        ).fetchall()
        findings = db.execute(
            "SELECT * FROM sensitive_findings WHERE bucket_id=%s",
            (bucket_id,)
        ).fetchall()

    result = calculate_exposure_score(
        dict(bucket),
        [dict(f) for f in files] if files else None,
        [dict(f) for f in findings] if findings else None,
    )
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════
# Feature 8: Breach Timeline
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/breach-timeline/<int:bucket_id>", methods=["GET"])
@auth_required
def get_breach_timeline(bucket_id):
    """Get exposure timeline for a bucket."""
    with get_db() as db:
        bucket = db.execute("SELECT * FROM buckets WHERE id=%s", (bucket_id,)).fetchone()
        if not bucket:
            return jsonify({"error": "Bucket not found"}), 404

        # Get scan history
        snapshots = db.execute("""
            SELECT ss.*, sj.started_at, sj.completed_at
            FROM scan_snapshots ss
            JOIN scan_jobs sj ON ss.scan_job_id=sj.id
            WHERE ss.bucket_id=%s ORDER BY ss.captured_at
        """, (bucket_id,)).fetchall()

    timeline = calculate_breach_timeline(dict(bucket))
    timeline["scan_history"] = [dict(s) for s in snapshots]
    timeline["total_scans"] = len(snapshots)
    return jsonify(timeline)


# ═══════════════════════════════════════════════════════════════════
# Feature 9: Industry/Sector View
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/industry/breakdown", methods=["GET"])
@auth_required
def industry_breakdown():
    """Get bucket exposure grouped by industry sector."""
    data = get_industry_breakdown()
    return jsonify({"industries": data, "count": len(data)})


@features_api.route("/industry/classify", methods=["POST"])
@auth_required
def classify_industry():
    """Classify a company name into an industry."""
    data = request.get_json(silent=True) or {}
    company = data.get("company_name", "")
    return jsonify({"company": company, "industry": classify_company_industry(company)})


# ═══════════════════════════════════════════════════════════════════
# Feature 10: Executive PDF Reports (HTML-based for browser print)
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/reports/executive", methods=["POST"])
@auth_required
def generate_executive_report():
    """Generate an executive summary report (HTML format for PDF export)."""
    with get_db() as db:
        stats = db.execute("""
            SELECT COUNT(*) as total, SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open_count,
                   SUM(file_count) as files, SUM(total_size_bytes) as size
            FROM buckets
        """).fetchone()
        risk_dist = db.execute("""
            SELECT risk_level, COUNT(*) FROM buckets WHERE risk_level IS NOT NULL GROUP BY risk_level
        """).fetchall()
        top_risk = db.execute("""
            SELECT b.name, b.status, b.risk_score, b.risk_level, b.file_count, b.company_name,
                   p.display_name as provider
            FROM buckets b JOIN providers p ON b.provider_id=p.id
            WHERE b.risk_score IS NOT NULL ORDER BY b.risk_score DESC LIMIT 10
        """).fetchall()
        sensitive_counts = db.execute("""
            SELECT category, COUNT(*) FROM sensitive_findings GROUP BY category ORDER BY COUNT(*) DESC
        """).fetchall()

    report = {
        "title": "CloudScan Executive Security Report",
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_buckets": stats[0],
            "open_buckets": stats[1],
            "total_files": stats[2] or 0,
            "total_size_bytes": stats[3] or 0,
        },
        "risk_distribution": {r[0]: r[1] for r in risk_dist},
        "top_risk_buckets": [dict(r) for r in top_risk],
        "sensitive_data": {r[0]: r[1] for r in sensitive_counts},
        "recommendations": [
            "Immediately review and restrict access to all critical-risk buckets",
            "Rotate any exposed credentials or API keys found in sensitive scans",
            "Enable bucket access logging across all cloud providers",
            "Implement naming policies to prevent predictable bucket patterns",
            "Set up continuous monitoring for all production assets",
            "Conduct a full compliance audit against applicable frameworks",
            "Establish an incident response plan for future exposures",
        ],
    }
    return jsonify(report)


# ═══════════════════════════════════════════════════════════════════
# Feature 11: Trend Analytics
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/trends", methods=["GET"])
@auth_required
def trend_analytics():
    """Get discovery and exposure trends over time."""
    days = min(int(request.args.get("days", 30)), 365)
    data = get_trend_data(days)
    return jsonify(data)


# ═══════════════════════════════════════════════════════════════════
# Feature 12: Attack Surface Mapping
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/attack-surface", methods=["GET"])
@auth_required
def attack_surface():
    """Get attack surface map for a company or all data."""
    company = request.args.get("company")
    data = get_attack_surface(company)
    return jsonify(data)


# ═══════════════════════════════════════════════════════════════════
# Feature 13: Slack/Teams/Discord Alerts
# (Extends existing notification_service + slack_configs)
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/alerts/channels", methods=["GET"])
@auth_required
def list_alert_channels():
    """List configured alert channels (Slack, Teams, Discord, email)."""
    user_id = g.user_id
    with get_db() as db:
        channels = db.execute("""
            SELECT id, type, name, config, is_active, last_used, failure_count
            FROM integrations WHERE user_id=%s AND type IN ('slack','teams','discord')
        """, (user_id,)).fetchall()
        slack = db.execute(
            "SELECT * FROM slack_configs WHERE user_id=%s", (user_id,)
        ).fetchall()
    return jsonify({
        "integrations": [dict(c) for c in channels],
        "slack_webhooks": [dict(s) for s in slack],
    })


@features_api.route("/alerts/channels", methods=["POST"])
@auth_required
def create_alert_channel():
    """Create a new alert channel (Teams/Discord webhook)."""
    data = request.get_json(silent=True) or {}
    channel_type = data.get("type", "").lower()
    if channel_type not in ("slack", "teams", "discord"):
        return jsonify({"error": "type must be slack, teams, or discord"}), 400

    from backend.app.models.database import IntegrationStore
    result = IntegrationStore.create(
        user_id=g.user_id,
        type=channel_type,
        name=data.get("name", f"{channel_type} webhook"),
        config=json.dumps({"webhook_url": data.get("webhook_url", ""), "channel": data.get("channel", "")}),
    )
    return jsonify(result), 201


# ═══════════════════════════════════════════════════════════════════
# Feature 14: Jira/Linear Ticket Creation
# (Extends existing integration infrastructure)
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/tickets/create", methods=["POST"])
@auth_required
def create_ticket():
    """Create a Jira/Linear ticket from an alert or finding."""
    data = request.get_json(silent=True) or {}
    platform = data.get("platform", "jira")
    title = data.get("title", "")
    description = data.get("description", "")
    priority = data.get("priority", "medium")
    bucket_id = data.get("bucket_id")
    alert_id = data.get("alert_id")

    if not title:
        return jsonify({"error": "title is required"}), 400

    # Store ticket reference
    with get_db() as db:
        db.execute("""
            INSERT INTO ticket_refs (user_id, platform, title, description, priority,
                                     bucket_id, alert_id, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'created')
        """, (g.user_id, platform, title, description, priority, bucket_id, alert_id))
        ticket = db.execute("SELECT * FROM ticket_refs ORDER BY id DESC LIMIT 1").fetchone()

    return jsonify(dict(ticket)), 201


@features_api.route("/tickets", methods=["GET"])
@auth_required
def list_tickets():
    """List created tickets."""
    with get_db() as db:
        tickets = db.execute("""
            SELECT tr.*, b.name as bucket_name
            FROM ticket_refs tr
            LEFT JOIN buckets b ON tr.bucket_id=b.id
            WHERE tr.user_id=%s ORDER BY tr.created_at DESC
        """, (g.user_id,)).fetchall()
    return jsonify({"tickets": [dict(t) for t in tickets]})


# ═══════════════════════════════════════════════════════════════════
# Feature 15: SIEM Export
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/export/siem", methods=["GET"])
@auth_required
def siem_export():
    """Export security events in SIEM-compatible format."""
    fmt = request.args.get("format", "cef")
    hours = min(int(request.args.get("hours", 24)), 720)
    events = export_siem_events(format=fmt, since_hours=hours)
    if fmt == "json":
        return jsonify({"events": [json.loads(e) for e in events], "count": len(events), "format": "json"})
    return jsonify({"events": events, "count": len(events), "format": "cef"})


# ═══════════════════════════════════════════════════════════════════
# Feature 16: API Webhooks (event subscriptions)
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/webhooks/subscriptions", methods=["POST"])
@auth_required
def create_webhook_subscription():
    """Subscribe to events via webhook."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    events = data.get("events", ["critical", "high"])
    if not url:
        return jsonify({"error": "url is required"}), 400

    from backend.app.models.database import WebhookStore
    result = WebhookStore.create(
        user_id=g.user_id, name=data.get("name", "Webhook"),
        url=url, event_types=events,
    )
    return jsonify(result), 201


@features_api.route("/webhooks/subscriptions", methods=["GET"])
@auth_required
def list_webhook_subscriptions():
    """List webhook subscriptions."""
    from backend.app.models.database import WebhookStore
    subs = WebhookStore.list_by_user(g.user_id)
    return jsonify({"subscriptions": subs})


# ═══════════════════════════════════════════════════════════════════
# Feature 17: Watchlist Continuous Monitoring (premium)
# (Extends existing watchlist infrastructure)
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/monitor/continuous", methods=["GET"])
@auth_required
def continuous_monitoring_status():
    """Get continuous monitoring status for all watchlists."""
    from backend.app.models.database import WatchlistStore, AlertStore
    watchlists = WatchlistStore.list_by_user(g.user_id)
    for wl in watchlists:
        wl["recent_alerts"] = AlertStore.count_unread(g.user_id)
    return jsonify({"watchlists": watchlists, "monitoring_active": True})


# ═══════════════════════════════════════════════════════════════════
# Feature 18: Team Workspaces
# (Extends existing organization infrastructure)
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/teams/workspace", methods=["GET"])
@auth_required
def get_team_workspace():
    """Get team workspace with shared scans and audit log."""
    from backend.app.models.database import OrgStore, AuditLogStore
    orgs = OrgStore.list_by_user(g.user_id)

    workspace = {
        "organizations": orgs,
        "shared_features": [
            "shared_scans", "shared_watchlists", "shared_reports",
            "team_audit_log", "role_based_access",
        ],
    }

    if orgs:
        org_id = orgs[0].get("id")
        workspace["recent_activity"] = AuditLogStore.list_by_user(g.user_id, limit=20)

    return jsonify(workspace)


# ═══════════════════════════════════════════════════════════════════
# Feature 19: Takedown Assistance
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/takedown/<int:bucket_id>", methods=["GET"])
@auth_required
def takedown_guide(bucket_id):
    """Get responsible disclosure / takedown guide for a bucket."""
    with get_db() as db:
        bucket = db.execute("""
            SELECT b.*, p.name as provider_name FROM buckets b
            JOIN providers p ON b.provider_id=p.id WHERE b.id=%s
        """, (bucket_id,)).fetchone()
    if not bucket:
        return jsonify({"error": "Bucket not found"}), 404

    bucket_dict = dict(bucket)
    guide = generate_takedown_guide(bucket_dict, bucket_dict.get("provider_name", ""))
    return jsonify(guide)


@features_api.route("/takedown/providers", methods=["GET"])
@auth_required
def list_abuse_contacts():
    """List all provider abuse contacts."""
    return jsonify({"providers": PROVIDER_ABUSE_CONTACTS})


# ═══════════════════════════════════════════════════════════════════
# Feature 20: Competitor Intelligence
# ═══════════════════════════════════════════════════════════════════

@features_api.route("/benchmark", methods=["GET"])
@auth_required
def competitor_benchmark():
    """Compare company exposure against industry peers."""
    company = request.args.get("company", "")
    if not company:
        return jsonify({"error": "company parameter is required"}), 400
    data = get_competitor_benchmark(company)
    return jsonify(data)
