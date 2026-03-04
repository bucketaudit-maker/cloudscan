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

from backend.app.models.database import (
    get_db, BucketStore, FileStore, ScanJobStore, init_db,
)
from backend.app.utils.auth import (
    auth_required, auth_required_strict, rate_limit,
    hash_password, verify_password, create_token, generate_api_key,
)
from backend.app.services.scan_service import ScanService

logger = logging.getLogger(__name__)

api = Blueprint("api", __name__, url_prefix="/api/v1")

# Global event queues for SSE subscribers
_sse_subscribers: list[queue.Queue] = []
_sse_lock = threading.Lock()


def broadcast_event(event_type: str, data: dict):
    """Push event to all SSE subscribers."""
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)


# Scan service singleton with event broadcasting
scan_service = ScanService(event_callback=broadcast_event)


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
            "SELECT id FROM users WHERE email=? OR username=?", (email, username)
        ).fetchone()
        if existing:
            return jsonify({"error": "Email or username already taken"}), 409

        api_key = generate_api_key()
        now = datetime.utcnow().isoformat()
        db.execute("""
            INSERT INTO users (email, username, password_hash, api_key, created_at, queries_reset_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (email, username, hash_password(password), api_key, now,
              (datetime.utcnow() + timedelta(days=1)).isoformat()))
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

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
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401
        if not user["is_active"]:
            return jsonify({"error": "Account disabled"}), 403
        db.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat(), user["id"]))

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
            "SELECT id, email, username, tier, api_key, created_at, last_login, queries_today FROM users WHERE id=?",
            (g.user_id,)
        ).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify(dict(user))


# ═══════════════════════════════════════════════════════════════════
# FILES — SEARCH
# ═══════════════════════════════════════════════════════════════════

@api.route("/files")
@auth_required
@rate_limit
def search_files():
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

    if not q and not ext and not provider:
        return jsonify({"error": "At least one search parameter required (q, ext, or provider)"}), 400

    start = time.monotonic()
    results = FileStore.search(
        query=q, extensions=ext, exclude_extensions=excl,
        min_size=min_size, max_size=max_size,
        provider=provider, bucket_name=bucket,
        sort=sort, page=page, per_page=per_page,
    )
    results["response_time_ms"] = int((time.monotonic() - start) * 1000)
    return jsonify(results)


@api.route("/files/random")
@auth_required
def random_files():
    count = min(request.args.get("count", 20, type=int), 100)
    with get_db() as db:
        rows = db.execute("""
            SELECT f.*, b.name as bucket_name, b.url as bucket_url, b.region,
                p.name as provider_name, p.display_name as provider_display
            FROM files f JOIN buckets b ON f.bucket_id=b.id
            JOIN providers p ON b.provider_id=p.id
            ORDER BY RANDOM() LIMIT ?
        """, (count,)).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


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
            "SELECT * FROM files WHERE bucket_id=? ORDER BY filepath LIMIT ? OFFSET ?",
            (bucket_id, per_page, (page - 1) * per_page),
        ).fetchall()
        total = db.execute("SELECT COUNT(*) FROM files WHERE bucket_id=?", (bucket_id,)).fetchone()[0]

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
@auth_required_strict
def create_scan():
    data = request.get_json(silent=True) or {}
    keywords = data.get("keywords", [])
    companies = data.get("companies", [])
    providers = data.get("providers", [])
    max_names = min(data.get("max_names", 1000), 10000)

    if not keywords and not companies:
        return jsonify({"error": "At least keywords or companies required"}), 400

    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # Start scan (runs in background thread)
    job = loop.run_until_complete(scan_service.start_discovery(
        keywords=keywords,
        companies=companies,
        providers=providers if providers else None,
        max_names=max_names,
        created_by=g.user_id,
    ))

    return jsonify(job), 202


@api.route("/scans/<int:job_id>")
@auth_required
def get_scan(job_id):
    job = ScanJobStore.get(job_id)
    if not job:
        return jsonify({"error": "Scan job not found"}), 404
    return jsonify(job)


@api.route("/scans")
@auth_required
def list_scans():
    return jsonify({"items": ScanJobStore.list_recent(50)})


@api.route("/scans/<int:job_id>/cancel", methods=["POST"])
@auth_required_strict
def cancel_scan(job_id):
    import asyncio
    loop = asyncio.new_event_loop()
    result = loop.run_until_complete(scan_service.cancel_scan(job_id))
    loop.close()
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

    def generate():
        try:
            # Send initial connection event
            yield f"event: connected\ndata: {json.dumps({'message': 'Connected to scan events'})}\n\n"

            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except queue.Empty:
                    # Send keepalive
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_subscribers:
                    _sse_subscribers.remove(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


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
