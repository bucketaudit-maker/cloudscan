"""
Flask API Blueprint — All REST endpoints + Server-Sent Events for real-time scan streaming.
"""
import json
import logging
import queue
import time
import threading
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, g, Response, stream_with_context

from backend.app.config import settings
from backend.app.models.database import (
    get_db, BucketStore, FileStore, ScanJobStore, init_db,
    WatchlistStore, AlertStore, MonitoredAssetStore, WebhookStore,
    SavedSearchStore, ApiLogStore,
    OrgStore, NotificationStore, NotificationPrefStore, SlackConfigStore,
    ReportStore, ReportScheduleStore, IntegrationStore, ComplianceStore,
    RemediationStore, seed_compliance_frameworks,
)
from backend.app.utils.auth import (
    auth_required, auth_required_strict, rate_limit,
    hash_password, verify_password, create_token, generate_api_key,
)
from backend.app.services.scan_service import ScanService
from backend.app.services.monitor_service import MonitoringService

logger = logging.getLogger(__name__)

api = Blueprint("api", __name__, url_prefix="/api/v1")

# Global event queues for SSE subscribers
_sse_subscribers: list[queue.Queue] = []
_sse_lock = threading.Lock()


def broadcast_event(event_type: str, data: dict):
    """Push event to all SSE subscribers."""
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        sub_count = len(_sse_subscribers)
        if sub_count == 0:
            logger.debug(f"SSE broadcast [{event_type}] — no subscribers connected")
            return
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)
        logger.debug(f"SSE broadcast [{event_type}] → {sub_count - len(dead)} subscribers")


# Scan service singleton with event broadcasting
scan_service = ScanService(event_callback=broadcast_event)


# ═══════════════════════════════════════════════════════════════════
# REQUEST LOGGING MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════

@api.before_request
def _start_timer():
    g._request_start = time.monotonic()


@api.after_request
def _log_request(response):
    # Skip SSE endpoint (long-lived connection) and health checks
    if request.path.endswith("/events/scans") or request.path.endswith("/health"):
        return response

    user_id = g.get("user_id")
    if user_id is None:
        return response

    elapsed_ms = int((time.monotonic() - getattr(g, "_request_start", time.monotonic())) * 1000)
    ApiLogStore.log(
        user_id=user_id,
        endpoint=request.path,
        method=request.method,
        query_params=request.query_string.decode("utf-8", errors="replace")[:500],
        ip_address=request.remote_addr or "",
        user_agent=(request.user_agent.string or "")[:200],
        response_status=response.status_code,
        response_time_ms=elapsed_ms,
    )
    return response


# ═══════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════

@api.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat(), "version": "1.0.0"})


# ═══════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════

@api.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not email or not username or not password:
        return jsonify({"error": "email, username, and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400

    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM users WHERE email=%s OR username=%s", (email, username)
        ).fetchone()
        if existing:
            return jsonify({"error": "Email or username already taken"}), 409

        api_key = generate_api_key()
        now = datetime.utcnow().isoformat()
        db.execute("""
            INSERT INTO users (email, username, password_hash, api_key, created_at, queries_reset_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (email, username, hash_password(password), api_key, now,
              (datetime.utcnow() + timedelta(days=1)).isoformat()))
        user = db.execute("SELECT * FROM users WHERE email=%s", (email,)).fetchone()

    token = create_token(user["id"], user["email"], user["tier"])
    return jsonify({
        "token": token,
        "api_key": api_key,
        "user": {
            "id": user["id"], "email": user["email"],
            "username": user["username"], "tier": user["tier"],
        },
    }), 201


@api.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=%s", (email,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401
        if not user["is_active"]:
            return jsonify({"error": "Account disabled"}), 403
        db.execute("UPDATE users SET last_login=%s WHERE id=%s", (datetime.utcnow().isoformat(), user["id"]))

    token = create_token(user["id"], user["email"], user["tier"])
    return jsonify({
        "token": token,
        "user": {
            "id": user["id"], "email": user["email"],
            "username": user["username"], "tier": user["tier"],
            "api_key": user["api_key"],
        },
    })


@api.route("/auth/me")
@auth_required_strict
def me():
    with get_db() as db:
        user = db.execute(
            "SELECT id, email, username, tier, api_key, created_at, last_login, queries_today FROM users WHERE id=%s",
            (g.user_id,)
        ).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify(dict(user))


@api.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400

    with get_db() as db:
        user = db.execute("SELECT id, email, username FROM users WHERE email=%s", (email,)).fetchone()
        if not user:
            # Don't reveal if email exists — always return success
            return jsonify({"message": "If that email exists, a reset link has been generated", "token": None})

        # Generate reset token (valid for 1 hour)
        import secrets
        token = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()

        # Invalidate any previous tokens for this user
        db.execute("UPDATE password_reset_tokens SET used=1 WHERE user_id=%s AND used=0", (user["id"],))

        db.execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
            (user["id"], token, expires),
        )

    logger.info(f"Password reset token generated for {email}")

    # In production: send email with reset link
    # For now: return token directly (self-hosted tool)
    return jsonify({
        "message": "Reset token generated. In production this would be emailed.",
        "token": token,
        "expires_in": "1 hour",
        "reset_url": f"/reset-password?token={token}",
    })


@api.route("/auth/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    new_password = data.get("password", "")

    if not token or not new_password:
        return jsonify({"error": "Token and new password required"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM password_reset_tokens WHERE token=%s AND used=0", (token,)
        ).fetchone()

        if not row:
            return jsonify({"error": "Invalid or expired reset token"}), 400

        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            db.execute("UPDATE password_reset_tokens SET used=1 WHERE id=%s", (row["id"],))
            return jsonify({"error": "Reset token has expired. Please request a new one."}), 400

        # Update password
        db.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                   (hash_password(new_password), row["user_id"]))

        # Mark token as used
        db.execute("UPDATE password_reset_tokens SET used=1 WHERE id=%s", (row["id"],))

        user = db.execute("SELECT id, email, tier FROM users WHERE id=%s", (row["user_id"],)).fetchone()

    logger.info(f"Password reset completed for user {row['user_id']}")

    # Return a fresh login token
    new_token = create_token(user["id"], user["email"], user["tier"])
    return jsonify({
        "message": "Password reset successfully",
        "token": new_token,
    })


@api.route("/auth/rotate-key", methods=["POST"])
@auth_required_strict
def rotate_api_key():
    new_key = generate_api_key()
    with get_db() as db:
        db.execute("UPDATE users SET api_key=%s WHERE id=%s", (new_key, g.user_id))
    return jsonify({"api_key": new_key, "message": "API key rotated successfully"})


@api.route("/auth/settings", methods=["PUT"])
@auth_required_strict
def update_user_settings():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username and not password:
        return jsonify({"error": "Nothing to update"}), 400

    with get_db() as db:
        if username:
            if len(username) < 3:
                return jsonify({"error": "Username must be at least 3 characters"}), 400
            existing = db.execute(
                "SELECT id FROM users WHERE username=%s AND id!=%s", (username, g.user_id)
            ).fetchone()
            if existing:
                return jsonify({"error": "Username already taken"}), 409
            db.execute("UPDATE users SET username=%s WHERE id=%s", (username, g.user_id))

        if password:
            if len(password) < 8:
                return jsonify({"error": "Password must be at least 8 characters"}), 400
            db.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (hash_password(password), g.user_id),
            )

        user = db.execute(
            "SELECT id, email, username, tier, created_at, last_login, queries_today FROM users WHERE id=%s",
            (g.user_id,),
        ).fetchone()

    return jsonify({"message": "Settings updated", "user": dict(user) if user else {}})


# ═══════════════════════════════════════════════════════════════════
# ACTIVITY LOG
# ═══════════════════════════════════════════════════════════════════

@api.route("/activity")
@auth_required_strict
def list_activity():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    return jsonify(ApiLogStore.list_by_user(g.user_id, page, per_page))


# ═══════════════════════════════════════════════════════════════════
# FILES — SEARCH
# ═══════════════════════════════════════════════════════════════════

@api.route("/files")
@auth_required
@rate_limit
def search_files():
    import re as _re

    q = request.args.get("q", "").strip()
    ext = [e.strip() for e in request.args.get("ext", "").split(",") if e.strip()] or None
    excl = [e.strip() for e in request.args.get("exclude_ext", "").split(",") if e.strip()] or None
    provider = request.args.get("provider")
    bucket = request.args.get("bucket")
    sort = request.args.get("sort", "relevance")
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    min_size = request.args.get("min_size", type=int)
    max_size = request.args.get("max_size", type=int)
    regex = request.args.get("regex", "").strip()

    if regex:
        try:
            _re.compile(regex)
        except _re.error:
            return jsonify({"error": "Invalid regex pattern"}), 400

    if not q and not ext and not provider and not regex:
        return jsonify({"error": "At least one search parameter required (q, ext, provider, or regex)"}), 400

    start = time.monotonic()
    results = FileStore.search(
        query=q, extensions=ext, exclude_extensions=excl,
        min_size=min_size, max_size=max_size,
        provider=provider, bucket_name=bucket,
        sort=sort, page=page, per_page=per_page,
        regex=regex or None,
    )
    results["response_time_ms"] = int((time.monotonic() - start) * 1000)
    return jsonify(results)


@api.route("/files/export")
@auth_required
@rate_limit
def export_files():
    """Export search results as CSV or JSON."""
    import csv
    import io
    import re as _re

    fmt = request.args.get("format", "csv").lower()
    if fmt not in ("csv", "json"):
        return jsonify({"error": "format must be csv or json"}), 400

    q = request.args.get("q", "").strip()
    ext = [e.strip() for e in request.args.get("ext", "").split(",") if e.strip()] or None
    provider = request.args.get("provider")
    regex = request.args.get("regex", "").strip()

    if regex:
        try:
            _re.compile(regex)
        except _re.error:
            return jsonify({"error": "Invalid regex pattern"}), 400

    if not q and not ext and not provider and not regex:
        return jsonify({"error": "At least one search parameter required"}), 400

    results = FileStore.search(
        query=q, extensions=ext, provider=provider,
        regex=regex or None, page=1, per_page=10000,
    )
    items = results.get("items", [])
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    if fmt == "json":
        return Response(
            json.dumps(items, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="cloudscan-export-{timestamp}.json"'},
        )

    columns = ["filepath", "filename", "extension", "size_bytes", "url",
               "bucket_name", "provider_name", "ai_classification", "last_modified"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for item in items:
        writer.writerow(item)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cloudscan-export-{timestamp}.csv"'},
    )


@api.route("/files/random")
@auth_required
def random_files():
    count = min(request.args.get("count", 20, type=int), 100)
    order_by = "random()" if settings.is_postgres else "RANDOM()"
    with get_db() as db:
        rows = db.execute(f"""
            SELECT f.*, b.name as bucket_name, b.url as bucket_url, b.region,
                p.name as provider_name, p.display_name as provider_display
            FROM files f JOIN buckets b ON f.bucket_id=b.id
            JOIN providers p ON b.provider_id=p.id
            ORDER BY {order_by} LIMIT %s
        """, (count,)).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


# ═══════════════════════════════════════════════════════════════════
# SAVED SEARCHES
# ═══════════════════════════════════════════════════════════════════

@api.route("/searches/saved", methods=["POST"])
@auth_required_strict
def create_saved_search():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    query_params = data.get("query_params", {})
    if not name:
        return jsonify({"error": "name is required"}), 400
    result = SavedSearchStore.create(g.user_id, name, query_params)
    return jsonify(result), 201


@api.route("/searches/saved")
@auth_required_strict
def list_saved_searches():
    return jsonify({"items": SavedSearchStore.list_by_user(g.user_id)})


@api.route("/searches/saved/<int:search_id>", methods=["DELETE"])
@auth_required_strict
def delete_saved_search(search_id):
    if not SavedSearchStore.delete(search_id, g.user_id):
        return jsonify({"error": "Saved search not found"}), 404
    return jsonify({"message": "Deleted"})


# ═══════════════════════════════════════════════════════════════════
# FILE PREVIEW
# ═══════════════════════════════════════════════════════════════════

@api.route("/files/<int:file_id>/preview")
@auth_required
@rate_limit
def file_preview(file_id):
    """Fetch first 4KB of a publicly accessible file for preview."""
    import html
    import urllib.request
    import urllib.error

    TEXT_EXTS = {
        "env", "txt", "log", "csv", "json", "xml", "yaml", "yml", "md",
        "ini", "cfg", "conf", "sh", "py", "js", "ts", "css", "html", "sql",
        "toml", "key", "pem", "htaccess", "gitignore", "dockerfile",
        "tf", "tfvars", "properties", "htpasswd",
    }

    with get_db() as db:
        row = db.execute(
            """SELECT f.*, b.name as bucket_name, p.name as provider_name
               FROM files f JOIN buckets b ON f.bucket_id=b.id
               JOIN providers p ON b.provider_id=p.id
               WHERE f.id=%s""",
            (file_id,),
        ).fetchone()

    if not row:
        return jsonify({"error": "File not found"}), 404

    f = dict(row)
    ext = (f.get("extension") or "").lower().lstrip(".")

    if ext not in TEXT_EXTS:
        return jsonify({
            "file_id": file_id,
            "preview_type": "binary",
            "content": None,
            "summary": f"Binary file ({ext.upper() or 'unknown'}, {f.get('size_bytes', 0):,} bytes)",
            "size_bytes": f.get("size_bytes", 0),
        })

    url = f.get("url", "")
    if not url:
        return jsonify({"file_id": file_id, "preview_type": "error", "error": "No URL available"})

    try:
        req = urllib.request.Request(url, headers={"Range": "bytes=0-4095"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read(4096)
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("latin-1", errors="replace")
            text = html.escape(text)
            return jsonify({
                "file_id": file_id,
                "preview_type": "text",
                "content": text,
                "truncated": f.get("size_bytes", 0) > 4096,
                "size_bytes": f.get("size_bytes", 0),
            })
    except Exception as e:
        return jsonify({
            "file_id": file_id,
            "preview_type": "error",
            "error": f"File not accessible: {str(e)[:100]}",
        })


# ═══════════════════════════════════════════════════════════════════
# ANALYTICS
# ═══════════════════════════════════════════════════════════════════

@api.route("/stats/timeline")
@auth_required
def stats_timeline():
    days = min(request.args.get("days", 30, type=int), 365)
    return jsonify(FileStore.get_timeline(days))


@api.route("/stats/breakdown")
@auth_required
def stats_breakdown():
    return jsonify(FileStore.get_breakdown())


# ═══════════════════════════════════════════════════════════════════
# BUCKETS
# ═══════════════════════════════════════════════════════════════════

@api.route("/buckets")
@auth_required
@rate_limit
def list_buckets():
    return jsonify(BucketStore.list_all(
        provider=request.args.get("provider"),
        status=request.args.get("status"),
        search=request.args.get("search"),
        page=request.args.get("page", 1, type=int),
        per_page=min(request.args.get("per_page", 50, type=int), 200),
    ))


@api.route("/buckets/<int:bucket_id>")
@auth_required
def get_bucket(bucket_id):
    b = BucketStore.get(bucket_id)
    if not b:
        return jsonify({"error": "Bucket not found"}), 404

    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 100, type=int), 500)

    with get_db() as db:
        files = db.execute(
            "SELECT * FROM files WHERE bucket_id=%s ORDER BY filepath LIMIT %s OFFSET %s",
            (bucket_id, per_page, (page - 1) * per_page),
        ).fetchall()
        total = db.execute("SELECT COUNT(*) FROM files WHERE bucket_id=%s", (bucket_id,)).fetchone()[0]

    b["files"] = {"items": [dict(f) for f in files], "total": total, "page": page, "per_page": per_page}
    return jsonify(b)


# ═══════════════════════════════════════════════════════════════════
# STATS
# ═══════════════════════════════════════════════════════════════════

@api.route("/stats")
def stats():
    return jsonify(FileStore.get_stats())


# ═══════════════════════════════════════════════════════════════════
# PROVIDERS
# ═══════════════════════════════════════════════════════════════════

@api.route("/providers")
def list_providers():
    with get_db() as db:
        rows = db.execute("SELECT * FROM providers ORDER BY id").fetchall()
        return jsonify({"items": [dict(r) for r in rows]})


# ═══════════════════════════════════════════════════════════════════
# SCANS — with real-time SSE streaming
# ═══════════════════════════════════════════════════════════════════

@api.route("/scans", methods=["POST"])
@auth_required
def create_scan():
    data = request.get_json(silent=True) or {}
    keywords = data.get("keywords", [])
    companies = data.get("companies", [])
    providers = data.get("providers", [])
    max_names = min(data.get("max_names", 1000), 10000)

    if not keywords and not companies:
        return jsonify({"error": "At least keywords or companies required"}), 400

    # start_discovery is SYNC — spawns a background thread internally
    job = scan_service.start_discovery(
        keywords=keywords,
        companies=companies,
        providers=providers if providers else None,
        max_names=max_names,
        created_by=g.get("user_id"),
    )

    return jsonify(job), 202


@api.route("/scans/<int:job_id>")
@auth_required
def get_scan(job_id):
    job = ScanJobStore.get(job_id)
    if not job:
        return jsonify({"error": "Scan job not found"}), 404
    return jsonify(job)


@api.route("/scans/debug")
def scan_debug():
    """Debug endpoint — shows active scan threads and recent job statuses."""
    active = scan_service.get_active_scans() if hasattr(scan_service, 'get_active_scans') else []
    recent = ScanJobStore.list_recent(5)
    with _sse_lock:
        sub_count = len(_sse_subscribers)
    return jsonify({
        "active_thread_ids": active,
        "sse_subscribers": sub_count,
        "recent_jobs": [{
            "id": j["id"], "status": j["status"],
            "names_checked": j.get("names_checked", 0),
            "buckets_found": j.get("buckets_found", 0),
            "files_indexed": j.get("files_indexed", 0),
            "errors": j.get("errors"),
            "started_at": j.get("started_at"),
            "completed_at": j.get("completed_at"),
        } for j in recent],
    })


@api.route("/scans")
@auth_required
def list_scans():
    return jsonify({"items": ScanJobStore.list_recent(50)})


@api.route("/scans/<int:job_id>/cancel", methods=["POST"])
@auth_required
def cancel_scan(job_id):
    result = scan_service.cancel_scan(job_id)
    if result:
        return jsonify({"message": "Scan cancelled"})
    return jsonify({"error": "Scan not found or already complete"}), 404


# ═══════════════════════════════════════════════════════════════════
# SERVER-SENT EVENTS — Real-time scan streaming
# ═══════════════════════════════════════════════════════════════════

@api.route("/events/scans")
def scan_events():
    """SSE endpoint for real-time scan progress and bucket discovery events."""
    q = queue.Queue(maxsize=1000)

    with _sse_lock:
        _sse_subscribers.append(q)
        logger.info(f"SSE client connected — {len(_sse_subscribers)} total subscribers")

    def generate():
        try:
            yield f"event: connected\ndata: {json.dumps({'message': 'Connected to scan events'})}\n\n"

            while True:
                try:
                    msg = q.get(timeout=15)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_subscribers:
                    _sse_subscribers.remove(q)
                logger.info(f"SSE client disconnected — {len(_sse_subscribers)} remaining")

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
        },
    )


# ═══════════════════════════════════════════════════════════════════
# ATTACK SURFACE MONITORING
# ═══════════════════════════════════════════════════════════════════

monitor_service = MonitoringService(event_callback=broadcast_event)


def _get_watchlist_owned(wl_id: int):
    """
    Return (watchlist_dict, None) if the current user owns the watchlist,
    else (None, (response, status_code)). Requires g.user_id (use with auth_required_strict).
    """
    if g.get("user_id") is None:
        return None, (jsonify({"error": "Authentication required"}), 401)
    wl = WatchlistStore.get(wl_id)
    if not wl:
        return None, (jsonify({"error": "Watchlist not found"}), 404)
    if wl.get("user_id") != g.user_id:
        return None, (jsonify({"error": "Watchlist not found"}), 404)
    return wl, None


@api.route("/monitor/watchlists", methods=["POST"])
@auth_required_strict
def create_watchlist():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    keywords = data.get("keywords", [])
    companies = data.get("companies", [])
    providers = data.get("providers", [])
    interval = data.get("scan_interval_hours", 24)

    if not name:
        return jsonify({"error": "Watchlist name required"}), 400
    if not keywords:
        return jsonify({"error": "At least one keyword required"}), 400

    wl = WatchlistStore.create(
        g.user_id, name, keywords, companies, providers, interval
    )
    return jsonify(wl), 201


@api.route("/monitor/watchlists")
@auth_required_strict
def list_watchlists():
    return jsonify({"items": WatchlistStore.list_by_user(g.user_id)})


@api.route("/monitor/watchlists/<int:wl_id>")
@auth_required_strict
def get_watchlist(wl_id):
    wl, err = _get_watchlist_owned(wl_id)
    if err:
        return err[0], err[1]
    wl["assets"] = MonitoredAssetStore.list_by_watchlist(wl_id)
    return jsonify(wl)


@api.route("/monitor/watchlists/<int:wl_id>", methods=["PUT"])
@auth_required_strict
def update_watchlist(wl_id):
    wl, err = _get_watchlist_owned(wl_id)
    if err:
        return err[0], err[1]
    data = request.get_json(silent=True) or {}
    allowed = {"name", "keywords", "companies", "providers", "scan_interval_hours", "is_active"}
    updates = {}
    for k, v in data.items():
        if k in allowed:
            updates[k] = json.dumps(v) if isinstance(v, (list, dict)) else v
    if updates:
        WatchlistStore.update(wl_id, **updates)
    return jsonify(WatchlistStore.get(wl_id))


@api.route("/monitor/watchlists/<int:wl_id>", methods=["DELETE"])
@auth_required_strict
def delete_watchlist(wl_id):
    wl, err = _get_watchlist_owned(wl_id)
    if err:
        return err[0], err[1]
    WatchlistStore.delete(wl_id)
    return jsonify({"message": "Deleted"})


@api.route("/monitor/watchlists/<int:wl_id>/scan", methods=["POST"])
@auth_required_strict
def trigger_watchlist_scan(wl_id):
    wl, err = _get_watchlist_owned(wl_id)
    if err:
        return err[0], err[1]
    monitor_service.scan_watchlist_async(wl)
    return jsonify({"message": "Scan started", "watchlist_id": wl_id}), 202


@api.route("/monitor/alerts")
@auth_required_strict
def list_alerts():
    return jsonify(AlertStore.list_by_user(
        g.user_id,
        unread_only=request.args.get("unread") == "true",
        severity=request.args.get("severity"),
        page=request.args.get("page", 1, type=int),
        per_page=min(request.args.get("per_page", 50, type=int), 200),
    ))


@api.route("/monitor/alerts/<int:alert_id>/read", methods=["POST"])
@auth_required_strict
def mark_alert_read(alert_id):
    if not AlertStore.get_for_user(alert_id, g.user_id):
        return jsonify({"error": "Alert not found"}), 404
    AlertStore.mark_read(alert_id, g.user_id)
    return jsonify({"message": "Marked read"})


@api.route("/monitor/alerts/read-all", methods=["POST"])
@auth_required_strict
def mark_all_alerts_read():
    AlertStore.mark_all_read(g.user_id)
    return jsonify({"message": "All marked read"})


@api.route("/monitor/alerts/<int:alert_id>/resolve", methods=["POST"])
@auth_required_strict
def resolve_alert(alert_id):
    if not AlertStore.get_for_user(alert_id, g.user_id):
        return jsonify({"error": "Alert not found"}), 404
    AlertStore.resolve(alert_id, g.user_id)
    return jsonify({"message": "Resolved"})


@api.route("/monitor/dashboard")
@auth_required_strict
def monitor_dashboard():
    return jsonify(WatchlistStore.get_dashboard(g.user_id))


# ═══════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════

@api.route("/monitor/webhooks", methods=["POST"])
@auth_required_strict
def create_webhook():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    url = data.get("url", "").strip()
    secret = data.get("secret", "").strip() or None
    event_types = data.get("event_types", ["critical", "high"])

    if not name or not url:
        return jsonify({"error": "name and url are required"}), 400
    if not url.startswith("http"):
        return jsonify({"error": "url must start with http:// or https://"}), 400

    wh = WebhookStore.create(g.user_id, name, url, secret, event_types)
    return jsonify(wh), 201


@api.route("/monitor/webhooks")
@auth_required_strict
def list_webhooks():
    return jsonify({"items": WebhookStore.list_by_user(g.user_id)})


@api.route("/monitor/webhooks/<int:wh_id>", methods=["PUT"])
@auth_required_strict
def update_webhook(wh_id):
    if not WebhookStore.get(wh_id, g.user_id):
        return jsonify({"error": "Webhook not found"}), 404
    data = request.get_json(silent=True) or {}
    WebhookStore.update(wh_id, g.user_id, **data)
    return jsonify(WebhookStore.get(wh_id, g.user_id))


@api.route("/monitor/webhooks/<int:wh_id>", methods=["DELETE"])
@auth_required_strict
def delete_webhook(wh_id):
    if not WebhookStore.delete(wh_id, g.user_id):
        return jsonify({"error": "Webhook not found"}), 404
    return jsonify({"message": "Deleted"})


@api.route("/monitor/webhooks/<int:wh_id>/test", methods=["POST"])
@auth_required_strict
def test_webhook(wh_id):
    wh = WebhookStore.get(wh_id, g.user_id)
    if not wh:
        return jsonify({"error": "Webhook not found"}), 404
    from backend.app.services.webhook_service import send_test
    result = send_test(wh)
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════
# AI FEATURES
# ═══════════════════════════════════════════════════════════════════

@api.route("/ai/status")
def ai_status():
    """Check AI provider status and available providers."""
    from backend.app.services.ai_service import is_ai_available
    from backend.app.services.providers import (
        list_providers as list_ai_providers,
        get_active_provider_name,
        get_provider,
    )

    active = get_provider()
    return jsonify({
        "available": is_ai_available(),
        "active_provider": get_active_provider_name() or None,
        "provider_display_name": active.display_name if active else None,
        "model_fast": active.model_fast if active else None,
        "model_quality": active.model_quality if active else None,
        "providers": list_ai_providers(),
        "features": [
            "classify", "risk_score", "nl_search",
            "report", "suggest_keywords", "prioritize_alerts",
        ],
    })


@api.route("/ai/provider", methods=["POST"])
@auth_required
def ai_set_provider():
    """Switch the active AI provider at runtime."""
    from backend.app.services.providers import set_provider, get_active_provider_name, get_provider

    data = request.get_json(silent=True) or {}
    provider_name = data.get("provider", "").strip().lower()

    if not provider_name:
        return jsonify({"error": "Provider name required"}), 400

    if not set_provider(provider_name):
        return jsonify({"error": f"Provider '{provider_name}' is not configured or not available"}), 400

    active = get_provider()
    return jsonify({
        "message": f"Switched to {active.display_name}",
        "active_provider": get_active_provider_name(),
        "model_fast": active.model_fast,
        "model_quality": active.model_quality,
    })


@api.route("/ai/classify/<int:bucket_id>", methods=["POST"])
@auth_required
def ai_classify_bucket(bucket_id):
    """Trigger AI classification for files in a bucket."""
    from backend.app.services.ai_service import classify_files
    bucket = BucketStore.get(bucket_id)
    if not bucket:
        return jsonify({"error": "Bucket not found"}), 404

    with get_db() as db:
        files = db.execute(
            "SELECT * FROM files WHERE bucket_id=%s LIMIT %s",
            (bucket_id, settings.AI_MAX_FILES_PER_BATCH),
        ).fetchall()

    if not files:
        return jsonify({"classified": 0, "results": []})

    classifications = classify_files(
        [dict(f) for f in files],
        bucket.get("name", ""),
        bucket.get("provider_name", ""),
    )
    if classifications:
        FileStore.update_classifications(bucket_id, classifications)
    return jsonify({"classified": len(classifications), "results": classifications})


@api.route("/ai/classifications")
@auth_required
def ai_get_classifications():
    """Get classification summary, optionally filtered by bucket."""
    bucket_id = request.args.get("bucket_id", type=int)
    summary = FileStore.get_classification_summary(bucket_id)
    return jsonify({"summary": summary})


@api.route("/ai/risk/<int:bucket_id>", methods=["POST"])
@auth_required
def ai_calculate_risk(bucket_id):
    """Calculate or recalculate risk score for a bucket."""
    from backend.app.services.ai_service import score_bucket_risk
    bucket = BucketStore.get(bucket_id)
    if not bucket:
        return jsonify({"error": "Bucket not found"}), 404

    summary = FileStore.get_classification_summary(bucket_id)
    classifications = [{"classification": k} for k in summary.keys()]
    risk = score_bucket_risk(bucket, classifications=classifications)
    BucketStore.update_risk(bucket_id, risk["risk_score"], risk["risk_level"])
    return jsonify(risk)


@api.route("/ai/search", methods=["POST"])
@auth_required
@rate_limit
def ai_search():
    """Natural language search: AI parses query intent, then runs structured search."""
    from backend.app.services.ai_service import parse_natural_language_query
    data = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"error": "Query required"}), 400

    start = time.monotonic()
    params = parse_natural_language_query(query)

    ext_str = params.get("ext", "")
    extensions = [e.strip() for e in ext_str.split(",") if e.strip()] if ext_str else None

    results = FileStore.search(
        query=params.get("q", ""),
        extensions=extensions,
        min_size=params.get("min_size"),
        max_size=params.get("max_size"),
        provider=params.get("provider"),
        bucket_name=params.get("bucket"),
        sort=params.get("sort", "relevance"),
        page=data.get("page", 1),
        per_page=min(data.get("per_page", 50), 200),
    )
    results["parsed_params"] = params
    results["original_query"] = query
    results["response_time_ms"] = int((time.monotonic() - start) * 1000)
    return jsonify(results)


@api.route("/ai/report", methods=["POST"])
@auth_required_strict
def ai_generate_report():
    """Generate AI security report from scan data."""
    from backend.app.services.ai_service import generate_security_report

    stats_data = FileStore.get_stats()
    classification_summary = FileStore.get_classification_summary()

    with get_db() as db:
        critical_buckets = db.execute("""
            SELECT b.*, p.name as provider_name
            FROM buckets b JOIN providers p ON b.provider_id=p.id
            WHERE b.risk_level IN ('critical', 'high')
            ORDER BY b.risk_score DESC LIMIT 20
        """).fetchall()

        risk_summary = {}
        for row in db.execute(
            "SELECT risk_level, COUNT(*) as cnt FROM buckets WHERE risk_level IS NOT NULL GROUP BY risk_level"
        ).fetchall():
            risk_summary[row["risk_level"]] = row["cnt"]

    scan_data = {
        "total_buckets": stats_data.get("total_buckets", 0),
        "open_buckets": stats_data.get("open_buckets", 0),
        "total_files": stats_data.get("total_files", 0),
        "total_size_bytes": stats_data.get("total_size_bytes", 0),
        "classification_summary": classification_summary,
        "risk_summary": risk_summary,
        "top_extensions": stats_data.get("top_extensions", []),
        "critical_buckets": [dict(b) for b in critical_buckets],
    }

    report = generate_security_report(scan_data)
    return jsonify(report)


@api.route("/ai/suggest-keywords", methods=["POST"])
@auth_required
def ai_suggest_keywords():
    """Generate smart bucket naming keywords for a company."""
    from backend.app.services.ai_service import suggest_keywords
    data = request.get_json(silent=True) or {}
    company = data.get("company", "").strip()
    if not company:
        return jsonify({"error": "Company name required"}), 400

    suggestions = suggest_keywords(company)
    return jsonify({"company": company, "suggestions": suggestions})


@api.route("/ai/prioritize-alerts", methods=["POST"])
@auth_required_strict
def ai_prioritize_alerts():
    """Re-prioritize user alerts using AI."""
    from backend.app.services.ai_service import prioritize_alerts
    alerts_data = AlertStore.list_by_user(
        g.user_id, unread_only=True, page=1, per_page=50)
    items = alerts_data.get("items", [])

    prioritized = prioritize_alerts(items)
    with get_db() as db:
        for a in prioritized:
            if a.get("ai_priority_score") is not None:
                db.execute(
                    "UPDATE alerts SET ai_priority_score=%s WHERE id=%s",
                    (a["ai_priority_score"], a["id"]),
                )
    return jsonify({"prioritized": len(prioritized), "alerts": prioritized})


# ═══════════════════════════════════════════════════════════════════
# ORGANIZATIONS
# ═══════════════════════════════════════════════════════════════════

@api.route("/orgs", methods=["POST"])
@auth_required_strict
def create_org():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    slug = data.get("slug", "").strip().lower().replace(" ", "-")
    if not name or not slug:
        return jsonify({"error": "name and slug required"}), 400
    if OrgStore.get_by_slug(slug):
        return jsonify({"error": "Slug already taken"}), 409
    org = OrgStore.create(g.user_id, name, slug)
    return jsonify(org), 201

@api.route("/orgs", methods=["GET"])
@auth_required_strict
def list_orgs():
    return jsonify(OrgStore.list_for_user(g.user_id))

@api.route("/orgs/<int:org_id>", methods=["GET"])
@auth_required_strict
def get_org(org_id):
    if not OrgStore.check_permission(org_id, g.user_id):
        return jsonify({"error": "Access denied"}), 403
    org = OrgStore.get(org_id)
    if not org:
        return jsonify({"error": "Not found"}), 404
    org["members"] = OrgStore.get_members(org_id)
    org["pending_invites"] = OrgStore.get_pending_invites(org_id)
    return jsonify(org)

@api.route("/orgs/<int:org_id>", methods=["PUT"])
@auth_required_strict
def update_org(org_id):
    if not OrgStore.check_permission(org_id, g.user_id, "admin"):
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json(silent=True) or {}
    with get_db() as db:
        updates, params = [], []
        for k in ("name", "settings"):
            if k in data:
                updates.append(f"{k}=%s")
                params.append(json.dumps(data[k]) if k == "settings" else data[k])
        if updates:
            params.append(org_id)
            db.execute(f"UPDATE organizations SET {','.join(updates)} WHERE id=%s", tuple(params))
    return jsonify(OrgStore.get(org_id))

@api.route("/orgs/<int:org_id>/invite", methods=["POST"])
@auth_required_strict
def invite_to_org(org_id):
    if not OrgStore.check_permission(org_id, g.user_id, "admin"):
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    role = data.get("role", "member")
    if not email:
        return jsonify({"error": "email required"}), 400
    invite = OrgStore.create_invite(org_id, email, role, g.user_id)
    return jsonify(invite), 201

@api.route("/orgs/accept-invite", methods=["POST"])
@auth_required_strict
def accept_org_invite():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"error": "token required"}), 400
    result = OrgStore.accept_invite(token, g.user_id)
    if not result:
        return jsonify({"error": "Invalid or expired invite"}), 400
    return jsonify(result)

@api.route("/orgs/<int:org_id>/members/<int:uid>", methods=["DELETE"])
@auth_required_strict
def remove_org_member(org_id, uid):
    if not OrgStore.check_permission(org_id, g.user_id, "admin"):
        return jsonify({"error": "Admin access required"}), 403
    if not OrgStore.remove_member(org_id, uid):
        return jsonify({"error": "Cannot remove owner or member not found"}), 400
    return jsonify({"ok": True})

@api.route("/orgs/<int:org_id>/members/<int:uid>", methods=["PUT"])
@auth_required_strict
def update_org_member_role(org_id, uid):
    if not OrgStore.check_permission(org_id, g.user_id, "admin"):
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json(silent=True) or {}
    role = data.get("role")
    if role not in ("viewer", "member", "admin"):
        return jsonify({"error": "Invalid role"}), 400
    OrgStore.update_role(org_id, uid, role)
    return jsonify({"ok": True})

@api.route("/orgs/<int:org_id>/switch", methods=["POST"])
@auth_required_strict
def switch_org(org_id):
    if not OrgStore.check_permission(org_id, g.user_id):
        return jsonify({"error": "Access denied"}), 403
    with get_db() as db:
        db.execute("UPDATE users SET active_org_id=%s WHERE id=%s", (org_id, g.user_id))
    return jsonify({"ok": True, "active_org_id": org_id})


# ═══════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════

@api.route("/notifications", methods=["GET"])
@auth_required_strict
def list_notifications():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    unread = request.args.get("unread_only", "false").lower() == "true"
    return jsonify(NotificationStore.list_by_user(g.user_id, unread_only=unread, page=page, per_page=per_page))

@api.route("/notifications/unread-count", methods=["GET"])
@auth_required_strict
def notification_unread_count():
    return jsonify({"count": NotificationStore.unread_count(g.user_id)})

@api.route("/notifications/<int:nid>/read", methods=["POST"])
@auth_required_strict
def mark_notification_read(nid):
    NotificationStore.mark_read(nid, g.user_id)
    return jsonify({"ok": True})

@api.route("/notifications/read-all", methods=["POST"])
@auth_required_strict
def mark_all_notifications_read():
    count = NotificationStore.mark_all_read(g.user_id)
    return jsonify({"ok": True, "marked": count})

@api.route("/notifications/prefs", methods=["GET"])
@auth_required_strict
def get_notification_prefs():
    return jsonify(NotificationPrefStore.get_for_user(g.user_id))

@api.route("/notifications/prefs", methods=["PUT"])
@auth_required_strict
def update_notification_prefs():
    data = request.get_json(silent=True) or {}
    channel = data.get("channel", "in_app")
    enabled = data.get("enabled", True)
    config = data.get("config")
    min_severity = data.get("min_severity", "medium")
    result = NotificationPrefStore.upsert(g.user_id, channel, enabled, config, min_severity)
    return jsonify(result)

@api.route("/notifications/slack", methods=["POST"])
@auth_required_strict
def create_slack_config():
    data = request.get_json(silent=True) or {}
    webhook_url = data.get("webhook_url", "").strip()
    if not webhook_url:
        return jsonify({"error": "webhook_url required"}), 400
    config = SlackConfigStore.create(g.user_id, webhook_url, data.get("channel_name"))
    return jsonify(config), 201

@api.route("/notifications/slack", methods=["DELETE"])
@auth_required_strict
def delete_slack_config():
    data = request.get_json(silent=True) or {}
    config_id = data.get("id")
    if not config_id:
        return jsonify({"error": "id required"}), 400
    SlackConfigStore.delete(config_id, g.user_id)
    return jsonify({"ok": True})

@api.route("/notifications/slack/test", methods=["POST"])
@auth_required_strict
def test_slack_notification():
    from backend.app.services.notification_service import _send_slack_message
    configs = SlackConfigStore.get_for_user(g.user_id)
    if not configs:
        return jsonify({"error": "No Slack config found"}), 404
    config = configs[0] if isinstance(configs, list) else configs
    try:
        _send_slack_message(config, "CloudScan Test", "This is a test notification from CloudScan.", "info")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════

@api.route("/reports/generate", methods=["POST"])
@auth_required_strict
def generate_report():
    data = request.get_json(silent=True) or {}
    report_type = data.get("report_type", "security")
    fmt = data.get("format", "json")

    with get_db() as db:
        bucket_count = db.execute("SELECT COUNT(*) FROM buckets").fetchone()[0]
        open_count = db.execute("SELECT COUNT(*) FROM buckets WHERE status='open'").fetchone()[0]
        file_count = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        alert_count = db.execute("SELECT COUNT(*) FROM alerts WHERE user_id=%s", (g.user_id,)).fetchone()[0]

    content = {
        "summary": {
            "total_buckets": bucket_count, "open_buckets": open_count,
            "total_files": file_count, "total_alerts": alert_count,
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "report_type": report_type,
    }

    if report_type == "compliance":
        content["compliance"] = ComplianceStore.get_dashboard(g.user_id)
    elif report_type == "executive":
        content["risk_summary"] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        with get_db() as db:
            for level in ("critical", "high", "medium", "low"):
                content["risk_summary"][level] = db.execute(
                    "SELECT COUNT(*) FROM buckets WHERE risk_level=%s", (level,)
                ).fetchone()[0]

    title = f"{report_type.title()} Report — {datetime.utcnow().strftime('%Y-%m-%d')}"
    report = ReportStore.create(g.user_id, title, report_type, json.dumps(content), fmt)
    return jsonify(report), 201

@api.route("/reports", methods=["GET"])
@auth_required_strict
def list_reports():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    return jsonify(ReportStore.list_by_user(g.user_id, page=page, per_page=per_page))

@api.route("/reports/<int:rid>", methods=["GET"])
@auth_required_strict
def get_report(rid):
    report = ReportStore.get(rid, g.user_id)
    if not report:
        return jsonify({"error": "Not found"}), 404
    return jsonify(report)

@api.route("/reports/<int:rid>", methods=["DELETE"])
@auth_required_strict
def delete_report(rid):
    ReportStore.delete(rid, g.user_id)
    return jsonify({"ok": True})

@api.route("/reports/<int:rid>/download", methods=["GET"])
@auth_required_strict
def download_report(rid):
    report = ReportStore.get(rid, g.user_id)
    if not report:
        return jsonify({"error": "Not found"}), 404
    content = report.get("content", "{}")
    if report.get("format") == "html":
        return Response(content, mimetype="text/html",
                       headers={"Content-Disposition": f"attachment; filename=report-{rid}.html"})
    return Response(content, mimetype="application/json",
                   headers={"Content-Disposition": f"attachment; filename=report-{rid}.json"})

@api.route("/reports/schedules", methods=["POST"])
@auth_required_strict
def create_report_schedule():
    data = request.get_json(silent=True) or {}
    report_type = data.get("report_type", "security")
    frequency = data.get("frequency", "weekly")
    if frequency not in ("daily", "weekly", "monthly"):
        return jsonify({"error": "Invalid frequency"}), 400
    schedule = ReportScheduleStore.create(g.user_id, report_type, frequency, data.get("config"))
    return jsonify(schedule), 201

@api.route("/reports/schedules", methods=["GET"])
@auth_required_strict
def list_report_schedules():
    return jsonify(ReportScheduleStore.list_by_user(g.user_id))

@api.route("/reports/schedules/<int:sid>", methods=["PUT"])
@auth_required_strict
def update_report_schedule(sid):
    data = request.get_json(silent=True) or {}
    ReportScheduleStore.update(sid, g.user_id, **data)
    return jsonify({"ok": True})

@api.route("/reports/schedules/<int:sid>", methods=["DELETE"])
@auth_required_strict
def delete_report_schedule(sid):
    ReportScheduleStore.delete(sid, g.user_id)
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════════
# INTEGRATIONS
# ═══════════════════════════════════════════════════════════════════

@api.route("/integrations", methods=["POST"])
@auth_required_strict
def create_integration():
    data = request.get_json(silent=True) or {}
    int_type = data.get("type", "").strip()
    name = data.get("name", "").strip()
    config = data.get("config", {})
    if not int_type or not name:
        return jsonify({"error": "type and name required"}), 400
    if int_type not in ("slack", "jira"):
        return jsonify({"error": "type must be slack or jira"}), 400
    integration = IntegrationStore.create(g.user_id, int_type, name, config)
    return jsonify(integration), 201

@api.route("/integrations", methods=["GET"])
@auth_required_strict
def list_integrations():
    int_type = request.args.get("type")
    return jsonify(IntegrationStore.list_by_user(g.user_id, type=int_type))

@api.route("/integrations/<int:iid>", methods=["GET"])
@auth_required_strict
def get_integration(iid):
    integration = IntegrationStore.get(iid, g.user_id)
    if not integration:
        return jsonify({"error": "Not found"}), 404
    return jsonify(integration)

@api.route("/integrations/<int:iid>", methods=["PUT"])
@auth_required_strict
def update_integration(iid):
    data = request.get_json(silent=True) or {}
    IntegrationStore.update(iid, g.user_id, **data)
    integration = IntegrationStore.get(iid, g.user_id)
    return jsonify(integration)

@api.route("/integrations/<int:iid>", methods=["DELETE"])
@auth_required_strict
def delete_integration(iid):
    IntegrationStore.delete(iid, g.user_id)
    return jsonify({"ok": True})

@api.route("/integrations/<int:iid>/test", methods=["POST"])
@auth_required_strict
def test_integration_endpoint(iid):
    from backend.app.services.integration_service import test_integration
    integration = IntegrationStore.get(iid, g.user_id)
    if not integration:
        return jsonify({"error": "Not found"}), 404
    result = test_integration(integration)
    return jsonify(result)

@api.route("/integrations/<int:iid>/send", methods=["POST"])
@auth_required_strict
def send_via_integration(iid):
    from backend.app.services.integration_service import send_slack_alert, create_jira_issue
    integration = IntegrationStore.get(iid, g.user_id)
    if not integration:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json(silent=True) or {}
    config = json.loads(integration["config"]) if isinstance(integration["config"], str) else integration["config"]
    int_type = integration["type"]
    if int_type == "slack":
        result = send_slack_alert(config, data)
    elif int_type == "jira":
        result = create_jira_issue(config, data)
    else:
        return jsonify({"error": "Unsupported type"}), 400
    return jsonify(result)

@api.route("/alerts/<int:alert_id>/create-jira", methods=["POST"])
@auth_required_strict
def create_jira_from_alert(alert_id):
    from backend.app.services.integration_service import create_jira_issue
    alert = AlertStore.get_for_user(alert_id, g.user_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    data = request.get_json(silent=True) or {}
    integration_id = data.get("integration_id")
    if not integration_id:
        jira_integrations = IntegrationStore.get_active_by_type(g.user_id, "jira")
        if not jira_integrations:
            return jsonify({"error": "No active Jira integration"}), 400
        integration = jira_integrations[0]
    else:
        integration = IntegrationStore.get(integration_id, g.user_id)
    if not integration:
        return jsonify({"error": "Integration not found"}), 404
    config = json.loads(integration["config"]) if isinstance(integration["config"], str) else integration["config"]
    result = create_jira_issue(config, alert)
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════
# COMPLIANCE
# ═══════════════════════════════════════════════════════════════════

@api.route("/compliance/frameworks", methods=["GET"])
@auth_required_strict
def list_compliance_frameworks():
    return jsonify(ComplianceStore.list_frameworks())

@api.route("/compliance/frameworks/<int:fid>", methods=["GET"])
@auth_required_strict
def get_compliance_framework(fid):
    fw = ComplianceStore.get_framework(fid)
    if not fw:
        return jsonify({"error": "Not found"}), 404
    fw["mappings"] = ComplianceStore.get_mappings(fid)
    return jsonify(fw)

@api.route("/compliance/check/<int:fid>", methods=["POST"])
@auth_required_strict
def run_compliance_check(fid):
    fw = ComplianceStore.get_framework(fid)
    if not fw:
        return jsonify({"error": "Framework not found"}), 404
    results = ComplianceStore.run_check(g.user_id, fid)
    passed = sum(1 for r in results if r["status"] == "pass")
    return jsonify({
        "framework": fw["display_name"],
        "total": len(results), "passed": passed,
        "failed": len(results) - passed,
        "score": round(passed / len(results) * 100) if results else 0,
        "results": results,
    })

@api.route("/compliance/results/<int:fid>", methods=["GET"])
@auth_required_strict
def get_compliance_results(fid):
    results = ComplianceStore.get_results(g.user_id, fid)
    return jsonify(results)

@api.route("/compliance/dashboard", methods=["GET"])
@auth_required_strict
def compliance_dashboard():
    return jsonify(ComplianceStore.get_dashboard(g.user_id))

@api.route("/compliance/export/<int:fid>", methods=["GET"])
@auth_required_strict
def export_compliance(fid):
    evidence = ComplianceStore.export_evidence(g.user_id, fid)
    if not evidence:
        return jsonify({"error": "Framework not found"}), 404
    return jsonify(evidence)


# ═══════════════════════════════════════════════════════════════════
# REMEDIATIONS
# ═══════════════════════════════════════════════════════════════════

@api.route("/remediations", methods=["POST"])
@auth_required_strict
def create_remediation():
    data = request.get_json(silent=True) or {}
    bucket_id = data.get("bucket_id")
    title = data.get("title", "").strip()
    if not bucket_id or not title:
        return jsonify({"error": "bucket_id and title required"}), 400
    rem = RemediationStore.create(
        bucket_id=bucket_id, user_id=g.user_id, title=title,
        description=data.get("description"), alert_id=data.get("alert_id"),
        assigned_to=data.get("assigned_to"), org_id=data.get("org_id"),
        priority=data.get("priority", "medium"), due_date=data.get("due_date"),
    )
    return jsonify(rem), 201

@api.route("/remediations", methods=["GET"])
@auth_required_strict
def list_remediations():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    status = request.args.get("status")
    assigned_to = request.args.get("assigned_to", type=int)
    return jsonify(RemediationStore.list_by_user(
        g.user_id, status=status, assigned_to=assigned_to, page=page, per_page=per_page))

@api.route("/remediations/<int:rid>", methods=["GET"])
@auth_required_strict
def get_remediation(rid):
    rem = RemediationStore.get(rid, g.user_id)
    if not rem:
        return jsonify({"error": "Not found"}), 404
    return jsonify(rem)

@api.route("/remediations/<int:rid>/status", methods=["PUT"])
@auth_required_strict
def update_remediation_status(rid):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ("open", "in_progress", "verified", "closed"):
        return jsonify({"error": "Invalid status"}), 400
    if not RemediationStore.update_status(rid, g.user_id, status):
        return jsonify({"error": "Not found or not authorized"}), 404
    return jsonify({"ok": True})

@api.route("/remediations/<int:rid>/assign", methods=["PUT"])
@auth_required_strict
def assign_remediation(rid):
    data = request.get_json(silent=True) or {}
    assigned_to = data.get("assigned_to")
    if not assigned_to:
        return jsonify({"error": "assigned_to required"}), 400
    if not RemediationStore.assign(rid, assigned_to, g.user_id):
        return jsonify({"error": "Not found or not authorized"}), 404
    return jsonify({"ok": True})

@api.route("/remediations/<int:rid>/notes", methods=["POST"])
@auth_required_strict
def add_remediation_note(rid):
    data = request.get_json(silent=True) or {}
    note = data.get("note", "").strip()
    if not note:
        return jsonify({"error": "note required"}), 400
    result = RemediationStore.add_note(rid, g.user_id, note)
    if not result:
        return jsonify({"error": "Not found"}), 404
    return jsonify(result)

@api.route("/remediations/dashboard", methods=["GET"])
@auth_required_strict
def remediation_dashboard():
    org_id = request.args.get("org_id", type=int)
    return jsonify(RemediationStore.get_dashboard(g.user_id, org_id=org_id))

@api.route("/alerts/<int:alert_id>/remediate", methods=["POST"])
@auth_required_strict
def create_remediation_from_alert(alert_id):
    alert = AlertStore.get_for_user(alert_id, g.user_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    data = request.get_json(silent=True) or {}
    rem = RemediationStore.create(
        bucket_id=alert.get("bucket_id", 0),
        user_id=g.user_id,
        title=data.get("title", alert.get("title", "Remediation")),
        description=data.get("description", alert.get("description")),
        alert_id=alert_id,
        priority=data.get("priority", alert.get("severity", "medium")),
        due_date=data.get("due_date"),
    )
    return jsonify(rem), 201


# ═══════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════

@api.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@api.errorhandler(500)
def server_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500