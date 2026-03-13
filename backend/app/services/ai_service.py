"""
AI Service — Multi-provider AI integration for all AI features.

Supports: Anthropic Claude, OpenAI GPT, Google Gemini, Ollama (local).
Graceful degradation: if no provider is configured/available, all methods
fall back to rule-based behavior and return deterministic results.
"""
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from backend.app.config import settings
from backend.app.services.providers import get_provider, get_active_provider_name

logger = logging.getLogger(__name__)


def is_ai_available() -> bool:
    """Check if AI features are available (any provider active)."""
    provider = get_provider()
    return provider is not None and provider.is_available()


def _call_llm(prompt: str, system: str = "", tier: str = "fast",
              max_tokens: int = 1024, temperature: float = 0.0) -> Optional[str]:
    """Low-level LLM API call via the active provider.

    Args:
        tier: "fast" or "quality" — selects the appropriate model for the active provider.
    Returns response text or None on failure.
    """
    provider = get_provider()
    if not provider:
        return None
    model = provider.model_quality if tier == "quality" else provider.model_fast
    return provider.call(prompt, system=system, model=model,
                         max_tokens=max_tokens, temperature=temperature)


def _extract_json(text: str):
    """Try to extract JSON from Claude's response, handling markdown fences."""
    if not text:
        return None
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try extracting from ```json ... ``` blocks
    match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass
    # Try finding first [ or { to end of matching bracket
    for start_char, end_char in [("[", "]"), ("{", "}")]:
        start = text.find(start_char)
        if start >= 0:
            end = text.rfind(end_char)
            if end > start:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    pass
    return None


# ═══════════════════════════════════════════════════════════════════
# FEATURE 1: AI SENSITIVE DATA CLASSIFIER
# ═══════════════════════════════════════════════════════════════════

CLASSIFICATION_CATEGORIES = [
    "credentials",    # API keys, tokens, passwords, secrets
    "pii",            # Personal data, user info, SSNs, emails
    "financial",      # Bank data, transactions, payment info
    "infrastructure", # Terraform, Docker, configs, CI/CD
    "source_code",    # Repositories, build artifacts, source files
    "medical",        # Health data, HIPAA-related
    "database",       # Database dumps, backups, migrations
    "generic",        # Low-risk / unclassifiable
]

RULE_BASED_PATTERNS = {
    "credentials": [
        ".env", "credentials", "secret", "password", "api_key",
        "apikey", "token", "private_key", "id_rsa", ".pem",
        ".key", ".pfx", "master.key", ".htpasswd", "oauth",
        ".p12", "keystore", "aws-credentials", "service-account",
    ],
    "pii": [
        "users", "customers", "personal", "ssn", "passport",
        "identity", "contact", "employee", "people", "profiles",
    ],
    "financial": [
        "bank", "payment", "transaction", "invoice", "financial",
        "accounting", "tax", "payroll", "billing", "revenue",
    ],
    "infrastructure": [
        "terraform", "tfstate", "docker", "compose",
        "kubernetes", "k8s", "ansible", "nginx", ".conf",
        "wp-config", "jenkinsfile", "circleci", "gitlab-ci",
    ],
    "source_code": [
        ".git", "package.json", "requirements.txt",
        "Makefile", "Gemfile", "go.mod", "Cargo.toml",
    ],
    "medical": [
        "health", "medical", "patient", "diagnosis", "hipaa",
        "prescription", "clinical", "ehr", "pharmacy",
    ],
    "database": [
        "backup.sql", "dump.sql", ".sql.gz", ".sql.bz2",
        ".sqlite", ".db", "migration", "mysqldump", "pgdump",
    ],
}


def classify_files(files: list[dict], bucket_name: str = "",
                   provider: str = "") -> list[dict]:
    """Classify files into sensitivity categories.

    Returns list of dicts:
        [{"filepath": ..., "classification": ..., "confidence": ...}, ...]
    """
    if not files:
        return []

    # Try AI classification first
    provider = get_provider()
    if provider and provider.is_available() and len(files) <= settings.AI_MAX_FILES_PER_BATCH:
        result = _ai_classify(files, bucket_name, provider)
        if result:
            return result

    # Fallback to rule-based
    return _rule_classify(files)


def _ai_classify(files: list[dict], bucket_name: str,
                 provider: str) -> Optional[list[dict]]:
    """Use AI to classify files."""
    file_summaries = []
    for f in files[:settings.AI_MAX_FILES_PER_BATCH]:
        size = f.get("size_bytes", 0)
        file_summaries.append(
            f"{f.get('filepath', '')} ({f.get('extension', '')}, {size} bytes)"
        )

    categories = ", ".join(CLASSIFICATION_CATEGORIES)
    prompt = f"""Classify these files from cloud bucket "{bucket_name}" ({provider}) by data sensitivity.

Categories: {categories}

Files:
{chr(10).join(file_summaries)}

Return a JSON array where each element has:
- "filepath": the exact filepath from above
- "classification": one of the categories
- "confidence": float 0.0-1.0

Return ONLY the JSON array, no other text."""

    system = (
        "You are a cloud security analyst. Classify files by their likely data sensitivity "
        "based on file paths, names, and extensions. Be conservative — mark files as the "
        "most sensitive applicable category. Return ONLY valid JSON."
    )

    response = _call_llm(prompt, system=system, max_tokens=4096)
    parsed = _extract_json(response)
    if isinstance(parsed, list):
        # Validate and normalize
        valid = []
        for item in parsed:
            if isinstance(item, dict) and "filepath" in item:
                cat = item.get("classification", "generic")
                if cat not in CLASSIFICATION_CATEGORIES:
                    cat = "generic"
                valid.append({
                    "filepath": item["filepath"],
                    "classification": cat,
                    "confidence": min(max(float(item.get("confidence", 0.7)), 0.0), 1.0),
                })
        if valid:
            return valid
    return None


def _rule_classify(files: list[dict]) -> list[dict]:
    """Fallback: pattern-matching classification."""
    results = []
    for f in files:
        fp = f.get("filepath", "").lower()
        fn = f.get("filename", "").lower()
        classification = "generic"
        confidence = 0.5

        for category, patterns in RULE_BASED_PATTERNS.items():
            for pattern in patterns:
                if pattern in fp or pattern in fn:
                    classification = category
                    confidence = 0.8
                    break
            if classification != "generic":
                break

        results.append({
            "filepath": f.get("filepath", ""),
            "classification": classification,
            "confidence": confidence,
        })
    return results


# ═══════════════════════════════════════════════════════════════════
# FEATURE 2: AI RISK SCORING
# ═══════════════════════════════════════════════════════════════════

RISK_WEIGHTS = {
    "credentials": 30,
    "pii": 25,
    "financial": 25,
    "medical": 25,
    "database": 20,
    "infrastructure": 15,
    "source_code": 10,
    "generic": 2,
}

RISKY_NAME_PATTERNS = [
    "backup", "prod", "production", "secret", "private", "internal",
    "admin", "credentials", "config", "database", "dump", "sensitive",
]


def score_bucket_risk(bucket: dict, files: list[dict] = None,
                      classifications: list[dict] = None) -> dict:
    """Score bucket risk 0-100.

    Returns {"risk_score": int, "risk_level": str, "factors": [str]}
    """
    score = 0
    factors = []

    # Factor 1: Bucket status
    status = bucket.get("status", "unknown")
    if status == "open":
        score += 20
        factors.append("Bucket is publicly accessible (+20)")
    elif status == "partial":
        score += 10
        factors.append("Bucket has partial access (+10)")

    # Factor 2: File count exposure
    file_count = bucket.get("file_count", 0)
    if file_count > 1000:
        score += 15
        factors.append(f"Large exposure: {file_count} files (+15)")
    elif file_count > 100:
        score += 10
        factors.append(f"Moderate exposure: {file_count} files (+10)")
    elif file_count > 0:
        score += 5
        factors.append(f"{file_count} files exposed (+5)")

    # Factor 3: File classifications
    if classifications:
        seen_cats = set()
        for c in classifications:
            cat = c.get("classification", "generic")
            if cat not in seen_cats:
                weight = RISK_WEIGHTS.get(cat, 0)
                if weight > 5:
                    score += weight
                    factors.append(f"Contains {cat} files (+{weight})")
                    seen_cats.add(cat)

    # Factor 4: Bucket name patterns
    name = bucket.get("name", "").lower()
    for pattern in RISKY_NAME_PATTERNS:
        if pattern in name:
            score += 10
            factors.append(f"Risky name pattern: '{pattern}' (+10)")
            break

    # Cap at 100
    score = min(score, 100)

    # Determine level
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

    return {"risk_score": score, "risk_level": level, "factors": factors}


# ═══════════════════════════════════════════════════════════════════
# FEATURE 3: NATURAL LANGUAGE SEARCH
# ═══════════════════════════════════════════════════════════════════

def parse_natural_language_query(query: str) -> dict:
    """Convert natural language to structured search parameters.

    Returns dict with keys: q, ext, provider, min_size, max_size, sort, bucket
    """
    if not is_ai_available():
        return {"q": query}

    prompt = f"""Convert this natural language search query into structured parameters for a cloud file search engine.

Query: "{query}"

Available parameters:
- q: keyword search string (the core search terms)
- ext: file extensions comma-separated (e.g. "sql,csv,json") — only if the user mentions specific file types
- provider: cloud provider filter (one of: aws, azure, gcp, digitalocean, alibaba) — only if mentioned
- min_size: minimum file size in bytes — only if size is mentioned
- max_size: maximum file size in bytes — only if size is mentioned
- sort: one of relevance, size_desc, size_asc, newest, oldest, filename — only if ordering is implied
- bucket: bucket name pattern — only if a specific bucket is mentioned

Return ONLY a JSON object with the applicable parameters. Omit parameters that aren't relevant to the query."""

    system = (
        "You are a search query parser. Convert natural language to structured "
        "search parameters. Return ONLY valid JSON, no explanation."
    )

    response = _call_llm(prompt, system=system, max_tokens=256)
    parsed = _extract_json(response)
    if isinstance(parsed, dict) and parsed.get("q"):
        return parsed
    return {"q": query}


# ═══════════════════════════════════════════════════════════════════
# FEATURE 4: AI SECURITY REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════

def generate_security_report(scan_data: dict) -> dict:
    """Generate an executive security report from scan results.

    Returns {"report": str (markdown), "generated_at": str, "model": str}
    """
    if not is_ai_available():
        return _generate_rule_based_report(scan_data)

    summary = _build_report_context(scan_data)

    prompt = f"""Generate an executive security assessment report based on these cloud storage scan findings.

{summary}

Structure the report with these sections:
## Executive Summary
2-3 sentences summarizing the overall security posture.

## Key Findings
Top 5 findings by severity, each with a risk level tag.

## Risk Overview
Summary of risk score distribution across discovered buckets.

## Sensitive Data Exposure
Breakdown by classification category with counts and implications.

## Remediation Recommendations
5-7 actionable steps prioritized by impact.

Use markdown formatting. Be specific with numbers from the data provided."""

    system = (
        "You are a senior cloud security analyst writing a report for executive leadership. "
        "Be precise, professional, and actionable. Use the data provided — do not invent numbers."
    )

    response = _call_llm(
        prompt, system=system,
        tier="quality",
        max_tokens=4096,
        temperature=0.3,
    )

    provider = get_provider()
    model_name = provider.model_quality if provider else "unknown"
    provider_name = get_active_provider_name() or "unknown"

    return {
        "report": response or "Report generation failed. AI service unavailable.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": f"{provider_name}/{model_name}",
    }


def _build_report_context(scan_data: dict) -> str:
    """Build a concise context string for report generation."""
    lines = [
        f"Total buckets scanned: {scan_data.get('total_buckets', 0)}",
        f"Open buckets: {scan_data.get('open_buckets', 0)}",
        f"Total files indexed: {scan_data.get('total_files', 0)}",
        f"Total data size: {scan_data.get('total_size_bytes', 0)} bytes",
    ]

    if scan_data.get("risk_summary"):
        lines.append(f"\nRisk distribution: {json.dumps(scan_data['risk_summary'])}")

    if scan_data.get("classification_summary"):
        lines.append(f"\nFile classifications: {json.dumps(scan_data['classification_summary'])}")

    if scan_data.get("top_extensions"):
        lines.append(f"\nTop file extensions: {json.dumps(scan_data['top_extensions'])}")

    critical_buckets = scan_data.get("critical_buckets", [])
    if critical_buckets:
        lines.append("\nCritical/High risk buckets:")
        for b in critical_buckets[:20]:
            lines.append(
                f"  - {b.get('name', '?')} ({b.get('provider_name', '?')}) — "
                f"Risk: {b.get('risk_score', 'N/A')}/{b.get('risk_level', 'N/A')}, "
                f"Files: {b.get('file_count', 0)}"
            )

    return "\n".join(lines)


def _generate_rule_based_report(scan_data: dict) -> dict:
    """Fallback: template-based report without AI."""
    total_b = scan_data.get("total_buckets", 0)
    open_b = scan_data.get("open_buckets", 0)
    total_f = scan_data.get("total_files", 0)
    class_summary = scan_data.get("classification_summary", {})

    sensitive_count = sum(
        v for k, v in class_summary.items() if k != "generic"
    )

    report = f"""## Executive Summary
CloudScan discovered **{total_b} buckets** across cloud providers, of which **{open_b}** are publicly accessible containing **{total_f}** indexed files. {"Sensitive files were detected requiring immediate attention." if sensitive_count > 0 else "No sensitive files were detected in this scan."}

## Key Findings
- {open_b} publicly accessible buckets found
- {total_f} files indexed across all providers
- {sensitive_count} files classified as sensitive
{f'- Credentials detected in {class_summary.get("credentials", 0)} files' if class_summary.get("credentials") else ''}
{f'- PII data found in {class_summary.get("pii", 0)} files' if class_summary.get("pii") else ''}

## Risk Overview
Risk scoring has been applied to all discovered buckets based on access level, file sensitivity, and naming patterns.

## Sensitive Data Exposure
"""
    if class_summary:
        for cat, count in sorted(class_summary.items(), key=lambda x: x[1], reverse=True):
            if cat != "generic":
                report += f"- **{cat.upper()}**: {count} files\n"
    else:
        report += "No classified files available.\n"

    report += """
## Remediation Recommendations
1. Review all publicly accessible buckets and restrict access where not intended
2. Rotate any exposed credentials or API keys immediately
3. Enable bucket access logging on all cloud providers
4. Implement bucket naming policies to avoid predictable patterns
5. Set up continuous monitoring for new exposures
"""

    return {
        "report": report,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": "rule-based",
    }


# ═══════════════════════════════════════════════════════════════════
# FEATURE 5: SMART KEYWORD GENERATION
# ═══════════════════════════════════════════════════════════════════

def suggest_keywords(company: str) -> list[str]:
    """Given a company name or domain, suggest likely bucket naming patterns."""
    if not is_ai_available():
        return _rule_based_keywords(company)

    prompt = f"""Given the company or organization "{company}", generate likely cloud storage bucket naming patterns that organizations commonly use.

Consider:
- Company name abbreviations and variants (with/without hyphens)
- Common suffixes: backup, data, prod, staging, dev, test, assets, logs, config, db, media, static, uploads
- Common patterns: company-env, company-service-env, company-data-year
- If it looks like a domain, use variations without the TLD
- Internal team/project name variations

Return a JSON array of 20-30 bucket name strings. Only lowercase, alphanumeric, and hyphens allowed.
Return ONLY the JSON array, no other text."""

    system = (
        "You are a cloud security expert generating realistic bucket naming patterns "
        "for security scanning. Return ONLY a JSON array of strings."
    )

    response = _call_llm(prompt, system=system, max_tokens=1024)
    parsed = _extract_json(response)
    if isinstance(parsed, list):
        valid = [n for n in parsed if isinstance(n, str) and re.match(r'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$', n)]
        if valid:
            return valid[:30]

    return _rule_based_keywords(company)


def _rule_based_keywords(company: str) -> list[str]:
    """Fallback keyword generation from company name."""
    c = re.sub(r"[^a-z0-9]", "-", company.lower().strip()).strip("-")
    if not c:
        return []

    # Remove common TLDs if it looks like a domain
    for tld in ["-com", "-io", "-org", "-net", "-co"]:
        if c.endswith(tld):
            c = c[:len(c) - len(tld)]

    suffixes = [
        "backup", "data", "prod", "staging", "dev", "test",
        "assets", "logs", "config", "db", "media", "static",
        "private", "public", "internal", "files", "storage",
        "uploads", "archive", "cdn",
    ]

    suggestions = [c]
    for s in suffixes:
        suggestions.append(f"{c}-{s}")

    # Abbreviation variant
    parts = c.split("-")
    if len(parts) > 1:
        abbr = "".join(p[0] for p in parts if p)
        if len(abbr) >= 2:
            suggestions.append(abbr)
            for s in suffixes[:10]:
                suggestions.append(f"{abbr}-{s}")

    # No-hyphen variant
    no_hyphen = c.replace("-", "")
    if no_hyphen != c:
        suggestions.append(no_hyphen)
        for s in suffixes[:6]:
            suggestions.append(f"{no_hyphen}-{s}")

    return suggestions


# ═══════════════════════════════════════════════════════════════════
# FEATURE 6: AI ALERT PRIORITIZATION
# ═══════════════════════════════════════════════════════════════════

def prioritize_alerts(alerts: list[dict], context: dict = None) -> list[dict]:
    """Re-score alerts using AI context analysis.

    Returns alerts with added 'ai_priority_score' (0-100), sorted by priority.
    """
    if not alerts:
        return []

    provider = get_provider()
    if provider and provider.is_available() and len(alerts) <= 50:
        result = _ai_prioritize(alerts, context)
        if result:
            return result

    return _rule_prioritize(alerts)


def _ai_prioritize(alerts: list[dict], context: dict = None) -> Optional[list[dict]]:
    """Use AI to score alert priority."""
    alert_summaries = []
    for a in alerts[:50]:
        alert_summaries.append(
            f"ID:{a['id']} type:{a.get('alert_type', '?')} "
            f"severity:{a.get('severity', '?')} title:{a.get('title', '?')}"
        )

    prompt = f"""Score these security alerts by actual risk priority (0-100, where 100 = most urgent).

Alerts:
{chr(10).join(alert_summaries)}

Prioritization criteria:
- Credential/secret exposure = highest priority (80-100)
- Production environment indicators = higher priority (70-90)
- Status changes (closed→open) = high priority (70-85)
- PII or financial data exposure = high priority (70-85)
- New bucket discovery = moderate (40-60)
- File count changes = lower (20-40)

Return a JSON array: [{{"id": <alert_id>, "ai_priority_score": <0-100>}}]
Return ONLY the JSON array."""

    system = "You are a security analyst triaging alerts. Score by actual risk. Return ONLY valid JSON."

    response = _call_llm(prompt, system=system, max_tokens=2048)
    parsed = _extract_json(response)
    if isinstance(parsed, list):
        score_map = {}
        for s in parsed:
            if isinstance(s, dict) and "id" in s and "ai_priority_score" in s:
                score_map[s["id"]] = min(max(int(s["ai_priority_score"]), 0), 100)
        if score_map:
            for a in alerts:
                a["ai_priority_score"] = score_map.get(a["id"], 50)
            return sorted(alerts, key=lambda x: x.get("ai_priority_score", 0), reverse=True)
    return None


def _rule_prioritize(alerts: list[dict]) -> list[dict]:
    """Fallback: rule-based priority scoring."""
    severity_scores = {
        "critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10,
    }
    type_boost = {
        "sensitive_file": 15, "status_change": 10,
        "new_bucket": 5, "new_files": 3, "bucket_closed": 0,
    }

    for a in alerts:
        base = severity_scores.get(a.get("severity", "info"), 10)
        boost = type_boost.get(a.get("alert_type", ""), 0)
        a["ai_priority_score"] = min(base + boost, 100)

    return sorted(alerts, key=lambda x: x["ai_priority_score"], reverse=True)
