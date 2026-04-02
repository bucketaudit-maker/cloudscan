"""
Features Service — All 20 new features for CloudScan Sprint 7.

Features:
  Discovery: 1. Subdomain bucket discovery, 2. GitHub leak scanning,
             3. Wildcard/regex search, 4. Scheduled re-scan with change detection
  Security:  5. Sensitive data classification, 6. Compliance mapping,
             7. Exposure severity scoring, 8. Breach timeline
  Intel:     9. Industry/sector view, 10. Executive PDF reports,
             11. Trend analytics, 12. Attack surface mapping
  Integrations: 13. Slack/Teams/Discord alerts, 14. Jira/Linear tickets,
                15. SIEM export, 16. API webhooks
  Monetization: 17. Watchlist continuous monitoring, 18. Team workspaces,
                19. Takedown assistance, 20. Competitor intelligence
"""
import json
import logging
import re
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional

from backend.app.config import settings
from backend.app.models.database import get_db

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# SENSITIVE DATA PATTERNS (Feature 5 enhanced)
# ═══════════════════════════════════════════════════════════════════

SENSITIVE_PATTERNS = {
    "api_key": {
        "patterns": [
            r"AKIA[0-9A-Z]{16}",           # AWS Access Key
            r"ghp_[a-zA-Z0-9]{36}",         # GitHub PAT
            r"sk-[a-zA-Z0-9]{48}",          # OpenAI key
            r"sk_live_[a-zA-Z0-9]+",        # Stripe live key
            r"pk_live_[a-zA-Z0-9]+",        # Stripe public key
            r"xox[bpsa]-[a-zA-Z0-9-]+",     # Slack token
        ],
        "severity": "critical",
        "compliance": ["PCI-DSS 3.4", "SOC2 CC6.1"],
    },
    "credentials": {
        "file_patterns": [
            r"\.env$", r"\.htpasswd$", r"\.pem$", r"\.key$", r"\.pfx$",
            r"id_rsa", r"credentials\.json", r"secret", r"password",
            r"master\.key", r"service.account.*\.json", r"\.p12$",
        ],
        "severity": "critical",
        "compliance": ["PCI-DSS 3.4", "SOC2 CC6.1", "GDPR Art.32"],
    },
    "pii": {
        "file_patterns": [
            r"ssn", r"social.security", r"\bssn\b", r"passport",
            r"personal.data", r"user.export", r"customer.list",
            r"employee", r"contact.list", r"phone.dump",
        ],
        "content_patterns": [
            r"\d{3}-\d{2}-\d{4}",           # SSN
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email
        ],
        "severity": "high",
        "compliance": ["GDPR Art.32", "HIPAA 164.312", "SOC2 CC6.1"],
    },
    "database": {
        "file_patterns": [
            r"\.sql$", r"\.sql\.gz$", r"\.dump$", r"\.bak$",
            r"\.mdb$", r"\.sqlite$", r"\.db$", r"mysqldump",
            r"pgdump", r"backup.*\.tar", r"database",
        ],
        "severity": "high",
        "compliance": ["PCI-DSS 3.4", "SOC2 CC6.1"],
    },
    "financial": {
        "file_patterns": [
            r"\.xls[x]?$", r"invoice", r"payment", r"credit",
            r"bank", r"transaction", r"payroll", r"tax.return",
            r"financial.report", r"revenue",
        ],
        "severity": "high",
        "compliance": ["PCI-DSS 3.4", "SOX 404"],
    },
    "medical": {
        "file_patterns": [
            r"patient", r"hipaa", r"medical", r"health",
            r"diagnosis", r"prescription", r"clinical",
            r"ehr", r"pharmacy", r"treatment",
        ],
        "severity": "critical",
        "compliance": ["HIPAA 164.312", "HIPAA 164.314"],
    },
}

COMPLIANCE_CONTROL_MAP = {
    "GDPR Art.32": {"framework": "GDPR", "name": "Security of Processing", "description": "Appropriate technical and organizational measures to ensure security"},
    "HIPAA 164.312": {"framework": "HIPAA", "name": "Technical Safeguards", "description": "Access controls and audit controls for ePHI"},
    "HIPAA 164.314": {"framework": "HIPAA", "name": "Organizational Requirements", "description": "Business associate contracts and requirements"},
    "SOC2 CC6.1": {"framework": "SOC2", "name": "Logical and Physical Access Controls", "description": "Restricting logical access to information assets"},
    "PCI-DSS 3.4": {"framework": "PCI-DSS", "name": "Render PAN Unreadable", "description": "Protect stored cardholder data"},
    "SOX 404": {"framework": "SOX", "name": "Internal Controls", "description": "Assessment of internal control over financial reporting"},
}

INDUSTRY_KEYWORDS = {
    "healthcare": ["health", "medical", "patient", "hospital", "pharma", "clinic", "dental", "care", "wellness"],
    "finance": ["bank", "capital", "invest", "financial", "insurance", "pay", "credit", "fund", "trade"],
    "technology": ["tech", "software", "cloud", "data", "ai", "cyber", "dev", "code", "digital", "app"],
    "retail": ["shop", "store", "retail", "commerce", "market", "buy", "sell", "product", "brand"],
    "education": ["edu", "university", "college", "school", "learn", "academic", "student", "campus"],
    "government": ["gov", "federal", "state", "municipal", "agency", "public", "defense", "military"],
    "media": ["media", "news", "broadcast", "publish", "content", "entertainment", "stream", "video"],
    "manufacturing": ["mfg", "factory", "industrial", "supply", "logistics", "warehouse", "production"],
}


# ═══════════════════════════════════════════════════════════════════
# Feature 5: Deep Sensitive Data Classification
# ═══════════════════════════════════════════════════════════════════

def deep_classify_files(files: list[dict]) -> list[dict]:
    """Run detailed sensitive pattern matching on files. Returns findings with severity."""
    findings = []
    for f in files:
        fp = f.get("filepath", "").lower()
        fn = f.get("filename", "").lower()
        for category, config in SENSITIVE_PATTERNS.items():
            matched = False
            for pattern in config.get("file_patterns", []):
                if re.search(pattern, fp, re.I) or re.search(pattern, fn, re.I):
                    matched = True
                    break
            if not matched:
                for pattern in config.get("patterns", []):
                    if re.search(pattern, fp) or re.search(pattern, fn):
                        matched = True
                        break
            if matched:
                findings.append({
                    "file_id": f.get("id"),
                    "filepath": f.get("filepath", ""),
                    "category": category,
                    "severity": config["severity"],
                    "compliance_controls": config.get("compliance", []),
                })
    return findings


# ═══════════════════════════════════════════════════════════════════
# Feature 6: Compliance Mapping
# ═══════════════════════════════════════════════════════════════════

def map_findings_to_compliance(findings: list[dict]) -> dict:
    """Map sensitive findings to violated compliance controls."""
    violations = {}
    for f in findings:
        for control_id in f.get("compliance_controls", []):
            if control_id not in violations:
                control = COMPLIANCE_CONTROL_MAP.get(control_id, {})
                violations[control_id] = {
                    "control_id": control_id,
                    "framework": control.get("framework", "Unknown"),
                    "name": control.get("name", control_id),
                    "description": control.get("description", ""),
                    "finding_count": 0,
                    "severity": "high",
                    "findings": [],
                }
            violations[control_id]["finding_count"] += 1
            violations[control_id]["findings"].append({
                "filepath": f["filepath"],
                "category": f["category"],
                "severity": f["severity"],
            })
    return violations


# ═══════════════════════════════════════════════════════════════════
# Feature 7: Exposure Severity Scoring (enhanced)
# ═══════════════════════════════════════════════════════════════════

SEVERITY_WEIGHTS = {
    "file_type": {
        ".env": 30, ".pem": 30, ".key": 30, ".sql": 25, ".db": 25,
        ".bak": 20, ".csv": 15, ".xls": 15, ".xlsx": 15, ".json": 10,
        ".xml": 10, ".pdf": 8, ".doc": 8, ".docx": 8,
    },
    "status_weight": {"open": 40, "partial": 20, "closed": 0, "error": 5, "unknown": 10},
}


def calculate_exposure_score(bucket: dict, files: list[dict] = None, findings: list[dict] = None) -> dict:
    """Enhanced exposure scoring: file types, volume, sensitivity, access level."""
    score = 0
    factors = []

    # Access level
    status = bucket.get("status", "unknown")
    access_score = SEVERITY_WEIGHTS["status_weight"].get(status, 10)
    score += access_score
    if access_score > 0:
        factors.append(f"Access level: {status} (+{access_score})")

    # File volume
    fc = bucket.get("file_count", 0)
    if fc > 10000:
        score += 20
        factors.append(f"Massive exposure: {fc:,} files (+20)")
    elif fc > 1000:
        score += 15
        factors.append(f"Large exposure: {fc:,} files (+15)")
    elif fc > 100:
        score += 10
        factors.append(f"Moderate: {fc:,} files (+10)")
    elif fc > 0:
        score += 5
        factors.append(f"{fc} files (+5)")

    # Data volume
    size = bucket.get("total_size_bytes", 0)
    if size > 1_000_000_000:  # 1GB
        score += 15
        factors.append("Over 1 GB of data (+15)")
    elif size > 100_000_000:
        score += 10
        factors.append("Over 100 MB of data (+10)")

    # Sensitive file types
    if files:
        for f in files:
            ext = f.get("extension", "").lower()
            weight = SEVERITY_WEIGHTS["file_type"].get(ext, 0)
            if weight > 0:
                score += min(weight, 30)
                factors.append(f"Sensitive file type: {ext} (+{weight})")
                break  # only count highest

    # Sensitive findings
    if findings:
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        if critical_count:
            score += min(critical_count * 15, 30)
            factors.append(f"{critical_count} critical findings (+{min(critical_count*15,30)})")
        if high_count:
            score += min(high_count * 10, 20)
            factors.append(f"{high_count} high-severity findings (+{min(high_count*10,20)})")

    score = min(score, 100)
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score >= 20:
        level = "low"
    else:
        level = "info"

    return {"exposure_score": score, "exposure_level": level, "factors": factors}


# ═══════════════════════════════════════════════════════════════════
# Feature 8: Breach Timeline
# ═══════════════════════════════════════════════════════════════════

def calculate_breach_timeline(bucket: dict) -> dict:
    """Calculate exposure window for a bucket."""
    first_seen = bucket.get("first_seen")
    last_scanned = bucket.get("last_scanned")
    status = bucket.get("status", "unknown")

    now = datetime.now(timezone.utc)
    timeline = {
        "bucket_id": bucket.get("id"),
        "bucket_name": bucket.get("name", ""),
        "current_status": status,
        "first_seen": first_seen,
        "last_scanned": last_scanned,
        "exposure_window_hours": None,
        "exposure_window_text": "Unknown",
        "risk_assessment": "unknown",
    }

    if first_seen and status in ("open", "partial"):
        try:
            fs = datetime.fromisoformat(first_seen.replace("Z", "+00:00")) if "Z" in first_seen else datetime.fromisoformat(first_seen).replace(tzinfo=timezone.utc)
            delta = now - fs
            hours = int(delta.total_seconds() / 3600)
            timeline["exposure_window_hours"] = hours
            if hours < 24:
                timeline["exposure_window_text"] = f"{hours} hours"
            elif hours < 720:
                timeline["exposure_window_text"] = f"{hours // 24} days"
            else:
                timeline["exposure_window_text"] = f"{hours // 720} months"

            if hours > 720:
                timeline["risk_assessment"] = "critical — prolonged exposure"
            elif hours > 168:
                timeline["risk_assessment"] = "high — exposed over a week"
            elif hours > 24:
                timeline["risk_assessment"] = "medium — multi-day exposure"
            else:
                timeline["risk_assessment"] = "low — recent exposure"
        except Exception:
            pass

    return timeline


# ═══════════════════════════════════════════════════════════════════
# Feature 9: Industry/Sector View
# ═══════════════════════════════════════════════════════════════════

def classify_company_industry(company_name: str) -> str:
    """Classify a company into an industry sector based on name keywords."""
    if not company_name:
        return "unknown"
    name_lower = company_name.lower()
    for industry, keywords in INDUSTRY_KEYWORDS.items():
        for kw in keywords:
            if kw in name_lower:
                return industry
    return "other"


def get_industry_breakdown() -> list[dict]:
    """Get bucket counts grouped by inferred industry."""
    with get_db() as db:
        rows = db.execute("""
            SELECT company_name, COUNT(*) as bucket_count,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open_count,
                   SUM(file_count) as total_files
            FROM buckets WHERE company_name IS NOT NULL AND company_name != ''
            GROUP BY company_name
        """).fetchall()

    industry_map = {}
    for r in rows:
        industry = classify_company_industry(r[0])
        if industry not in industry_map:
            industry_map[industry] = {"industry": industry, "companies": 0, "buckets": 0, "open_buckets": 0, "total_files": 0}
        industry_map[industry]["companies"] += 1
        industry_map[industry]["buckets"] += r[1]
        industry_map[industry]["open_buckets"] += r[2]
        industry_map[industry]["total_files"] += (r[3] or 0)

    return sorted(industry_map.values(), key=lambda x: x["buckets"], reverse=True)


# ═══════════════════════════════════════════════════════════════════
# Feature 11: Trend Analytics
# ═══════════════════════════════════════════════════════════════════

def get_trend_data(days: int = 30) -> dict:
    """Get bucket/file discovery trends over time."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with get_db() as db:
        # Buckets discovered per day
        bucket_trend = db.execute("""
            SELECT SUBSTRING(first_seen, 1, 10) as day, COUNT(*) as count,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open_count
            FROM buckets WHERE first_seen >= %s
            GROUP BY SUBSTRING(first_seen, 1, 10) ORDER BY day
        """, (cutoff,)).fetchall()

        # Files indexed per day
        file_trend = db.execute("""
            SELECT SUBSTRING(indexed_at, 1, 10) as day, COUNT(*) as count, SUM(size_bytes) as total_size
            FROM files WHERE indexed_at >= %s
            GROUP BY SUBSTRING(indexed_at, 1, 10) ORDER BY day
        """, (cutoff,)).fetchall()

        # Status changes
        status_trend = db.execute("""
            SELECT diff_type, COUNT(*) as count, SUBSTRING(created_at, 1, 10) as day
            FROM scan_diffs WHERE created_at >= %s
            GROUP BY diff_type, SUBSTRING(created_at, 1, 10) ORDER BY day
        """, (cutoff,)).fetchall()

    return {
        "period_days": days,
        "bucket_trend": [{"date": r[0], "discovered": r[1], "open": r[2]} for r in bucket_trend],
        "file_trend": [{"date": r[0], "indexed": r[1], "total_size": r[2] or 0} for r in file_trend],
        "status_changes": [{"type": r[0], "count": r[1], "date": r[2]} for r in status_trend],
    }


# ═══════════════════════════════════════════════════════════════════
# Feature 12: Attack Surface Mapping
# ═══════════════════════════════════════════════════════════════════

def get_attack_surface(company_name: str = None) -> dict:
    """Build attack surface map for a company or all data."""
    with get_db() as db:
        if company_name:
            buckets = db.execute("""
                SELECT b.*, p.name as provider_name, p.display_name
                FROM buckets b JOIN providers p ON b.provider_id=p.id
                WHERE b.company_name=%s ORDER BY b.risk_score DESC NULLS LAST
            """, (company_name,)).fetchall()
        else:
            buckets = db.execute("""
                SELECT b.*, p.name as provider_name, p.display_name
                FROM buckets b JOIN providers p ON b.provider_id=p.id
                ORDER BY b.risk_score DESC NULLS LAST LIMIT 500
            """).fetchall()

    if not buckets:
        return {"nodes": [], "summary": {}}

    cols = [d[0] for d in buckets[0].keys()] if hasattr(buckets[0], 'keys') else None

    # Build surface map
    providers = {}
    regions = {}
    total_files = 0
    total_size = 0
    statuses = {"open": 0, "closed": 0, "partial": 0, "error": 0, "unknown": 0}

    nodes = []
    for b in buckets:
        row = dict(b) if hasattr(b, 'keys') else dict(zip(range(len(b)), b))
        prov = row.get("provider_name", "unknown")
        region = row.get("region", "unknown")
        status = row.get("status", "unknown")

        providers[prov] = providers.get(prov, 0) + 1
        regions[region] = regions.get(region, 0) + 1
        statuses[status] = statuses.get(status, 0) + 1
        total_files += (row.get("file_count", 0) or 0)
        total_size += (row.get("total_size_bytes", 0) or 0)

        nodes.append({
            "id": row.get("id"),
            "name": row.get("name"),
            "provider": prov,
            "region": region,
            "status": status,
            "risk_score": row.get("risk_score"),
            "risk_level": row.get("risk_level"),
            "file_count": row.get("file_count", 0),
            "company_name": row.get("company_name"),
        })

    return {
        "company": company_name,
        "nodes": nodes,
        "summary": {
            "total_buckets": len(buckets),
            "providers": providers,
            "regions": regions,
            "statuses": statuses,
            "total_files": total_files,
            "total_size_bytes": total_size,
        },
    }


# ═══════════════════════════════════════════════════════════════════
# Feature 1: Subdomain-based bucket discovery
# ═══════════════════════════════════════════════════════════════════

CT_LOG_SUBDOMAINS = [
    "s3", "storage", "assets", "cdn", "backup", "data", "files",
    "media", "static", "uploads", "images", "docs", "archive",
    "logs", "config", "dev", "staging", "prod", "test", "internal",
]


def generate_subdomain_names(domain: str) -> list[str]:
    """Generate bucket names from common subdomain patterns for a domain."""
    # Strip protocol and www
    domain = re.sub(r"https?://", "", domain).strip("/")
    domain = re.sub(r"^www\.", "", domain)
    base = domain.split(".")[0]

    names = []
    # Direct domain patterns
    names.append(base)
    names.append(domain.replace(".", "-"))

    for sub in CT_LOG_SUBDOMAINS:
        names.append(f"{base}-{sub}")
        names.append(f"{sub}-{base}")
        names.append(f"{sub}.{base}")

    # Common cloud patterns
    for env in ["dev", "staging", "prod"]:
        names.append(f"{base}-{env}")
        names.append(f"{env}-{base}")

    return list(set(n.lower() for n in names if 3 <= len(n) <= 63))


# ═══════════════════════════════════════════════════════════════════
# Feature 2: GitHub Leak Scanning patterns
# ═══════════════════════════════════════════════════════════════════

GITHUB_BUCKET_PATTERNS = [
    r"s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])",
    r"https?://([a-z0-9.-]+)\.s3[.-]",
    r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])",
    r"https?://([a-z0-9.-]+)\.blob\.core\.windows\.net",
    r"BUCKET[_=:\s]+['\"]?([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])['\"]?",
]


def extract_bucket_refs_from_text(text: str) -> list[dict]:
    """Extract bucket name references from code/text (e.g., GitHub search results)."""
    refs = []
    seen = set()
    for pattern in GITHUB_BUCKET_PATTERNS:
        for match in re.finditer(pattern, text, re.I):
            name = match.group(1).lower()
            if name not in seen and 3 <= len(name) <= 63:
                seen.add(name)
                refs.append({"name": name, "source": "code_search", "pattern": pattern[:30]})
    return refs


# ═══════════════════════════════════════════════════════════════════
# Feature 3: Wildcard/Regex search
# ═══════════════════════════════════════════════════════════════════

def search_buckets_regex(pattern: str, limit: int = 100) -> list[dict]:
    """Search buckets using SQL LIKE pattern (converted from user wildcard)."""
    # Convert user-friendly wildcards to SQL LIKE
    sql_pattern = pattern.replace("*", "%").replace("?", "_")
    with get_db() as db:
        rows = db.execute("""
            SELECT b.id, b.name, b.status, b.region, b.file_count, b.company_name,
                   b.risk_score, b.risk_level, p.display_name as provider_name
            FROM buckets b JOIN providers p ON b.provider_id=p.id
            WHERE b.name LIKE %s
            ORDER BY b.risk_score DESC NULLS LAST LIMIT %s
        """, (sql_pattern, limit)).fetchall()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════
# Feature 15: SIEM Export
# ═══════════════════════════════════════════════════════════════════

def export_siem_events(format: str = "cef", since_hours: int = 24) -> list[str]:
    """Export security events in SIEM-compatible format (CEF or JSON)."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    with get_db() as db:
        alerts = db.execute("""
            SELECT a.*, b.name as bucket_name, b.url as bucket_url
            FROM alerts a LEFT JOIN buckets b ON a.bucket_id=b.id
            WHERE a.created_at >= %s
            ORDER BY a.created_at DESC
        """, (cutoff,)).fetchall()

    events = []
    for a in alerts:
        row = dict(a)
        if format == "cef":
            # Common Event Format
            severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
            sev = severity_map.get(row.get("severity", "info"), 1)
            cef = (
                f"CEF:0|CloudScan|BucketAudit|1.0|{row.get('alert_type', 'unknown')}|"
                f"{row.get('title', '')}|{sev}|"
                f"src={row.get('bucket_url', '')} "
                f"cs1={row.get('bucket_name', '')} cs1Label=BucketName "
                f"cs2={row.get('severity', 'info')} cs2Label=Severity "
                f"rt={row.get('created_at', '')}"
            )
            events.append(cef)
        else:
            events.append(json.dumps({
                "timestamp": row.get("created_at"),
                "event_type": row.get("alert_type"),
                "severity": row.get("severity"),
                "title": row.get("title"),
                "description": row.get("description"),
                "bucket_name": row.get("bucket_name"),
                "bucket_url": row.get("bucket_url"),
                "source": "CloudScan",
            }))
    return events


# ═══════════════════════════════════════════════════════════════════
# Feature 19: Takedown Assistance
# ═══════════════════════════════════════════════════════════════════

PROVIDER_ABUSE_CONTACTS = {
    "aws": {
        "name": "Amazon Web Services",
        "abuse_url": "https://support.aws.amazon.com/#/contacts/report-abuse",
        "abuse_email": "abuse@amazonaws.com",
        "steps": [
            "Document the exposed bucket URL and contents",
            "File an abuse report at the AWS abuse URL",
            "Include bucket name, region, and description of sensitive data",
            "AWS typically responds within 24-48 hours",
            "Follow up if no response after 72 hours",
        ],
    },
    "azure": {
        "name": "Microsoft Azure",
        "abuse_url": "https://msrc.microsoft.com/report/abuse",
        "abuse_email": "cert@microsoft.com",
        "steps": [
            "Document the exposed container URL",
            "Submit via Microsoft Security Response Center",
            "Include storage account name and container details",
            "Microsoft typically triages within 24 hours",
        ],
    },
    "gcp": {
        "name": "Google Cloud Platform",
        "abuse_url": "https://support.google.com/code/contact/cloud_platform_report",
        "abuse_email": "gcp-abuse@google.com",
        "steps": [
            "Document the exposed bucket URL",
            "File report via Google Cloud abuse form",
            "Include bucket name and description of sensitive content",
            "Google typically responds within 1-3 business days",
        ],
    },
    "digitalocean": {
        "name": "DigitalOcean",
        "abuse_url": "https://www.digitalocean.com/company/contact#abuse",
        "abuse_email": "abuse@digitalocean.com",
        "steps": [
            "Document the exposed Space URL",
            "Email DigitalOcean abuse team with details",
            "Include Space name, region, and sensitive content description",
        ],
    },
    "alibaba": {
        "name": "Alibaba Cloud",
        "abuse_url": "https://www.alibabacloud.com/report",
        "abuse_email": "abuse@service.alibaba.com",
        "steps": [
            "Document the exposed OSS bucket URL",
            "Submit report via Alibaba Cloud abuse portal",
            "Include bucket name and region details",
        ],
    },
}


def generate_takedown_guide(bucket: dict, provider_name: str) -> dict:
    """Generate takedown/responsible disclosure guide for a bucket."""
    contact = PROVIDER_ABUSE_CONTACTS.get(provider_name, {})
    return {
        "bucket_name": bucket.get("name", ""),
        "provider": provider_name,
        "provider_display": contact.get("name", provider_name),
        "abuse_url": contact.get("abuse_url", ""),
        "abuse_email": contact.get("abuse_email", ""),
        "steps": contact.get("steps", ["Contact the cloud provider's abuse team with details of the exposure."]),
        "email_template": _generate_disclosure_email(bucket, contact),
        "disclaimer": "This is a responsible disclosure guide. Ensure you have proper authorization before reporting.",
    }


def _generate_disclosure_email(bucket: dict, contact: dict) -> str:
    return f"""Subject: Responsible Disclosure — Exposed Cloud Storage Bucket

Dear {contact.get('name', 'Security')} Team,

I am writing to report a publicly accessible cloud storage bucket that may contain sensitive data.

Bucket Details:
- Name: {bucket.get('name', 'N/A')}
- URL: {bucket.get('url', 'N/A')}
- Region: {bucket.get('region', 'N/A')}
- Status: {bucket.get('status', 'N/A')}
- Files Exposed: {bucket.get('file_count', 'N/A')}

This bucket appears to be misconfigured with public access enabled. I am reporting this as a responsible disclosure to help protect the data owner.

Please investigate and take appropriate action to secure this resource.

Regards,
[Your Name]
CloudScan Security Platform"""


# ═══════════════════════════════════════════════════════════════════
# Feature 20: Competitor Intelligence (anonymized)
# ═══════════════════════════════════════════════════════════════════

def get_competitor_benchmark(company_name: str) -> dict:
    """Compare a company's exposure against industry peers (anonymized)."""
    industry = classify_company_industry(company_name)

    with get_db() as db:
        # Get target company stats
        company_stats = db.execute("""
            SELECT COUNT(*) as buckets,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open_buckets,
                   SUM(file_count) as total_files,
                   AVG(risk_score) as avg_risk
            FROM buckets WHERE company_name=%s
        """, (company_name,)).fetchone()

        # Get all companies for benchmarking
        all_companies = db.execute("""
            SELECT company_name, COUNT(*) as buckets,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open_buckets,
                   AVG(risk_score) as avg_risk
            FROM buckets WHERE company_name IS NOT NULL AND company_name != ''
            GROUP BY company_name
        """).fetchall()

    if not company_stats or not all_companies:
        return {"company": company_name, "industry": industry, "benchmark": None}

    # Calculate percentiles
    risks = sorted([r[3] or 0 for r in all_companies])
    company_risk = company_stats[3] or 0
    percentile = sum(1 for r in risks if r <= company_risk) / max(len(risks), 1) * 100

    return {
        "company": company_name,
        "industry": industry,
        "stats": {
            "total_buckets": company_stats[0],
            "open_buckets": company_stats[1],
            "total_files": company_stats[2] or 0,
            "avg_risk_score": round(company_risk, 1),
        },
        "benchmark": {
            "total_companies": len(all_companies),
            "risk_percentile": round(percentile, 1),
            "industry_avg_risk": round(sum(r[3] or 0 for r in all_companies) / max(len(all_companies), 1), 1),
            "better_than_percent": round(100 - percentile, 1),
        },
    }
