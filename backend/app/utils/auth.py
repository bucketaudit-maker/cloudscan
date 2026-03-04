"""
Authentication utilities — password hashing, JWT tokens, decorators.
"""
import base64
import functools
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta

from flask import request, jsonify, g

from backend.app.config import settings
from backend.app.models.database import get_db

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# PASSWORD HASHING (PBKDF2-SHA256)
# ═══════════════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}:{h.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, h = stored_hash.split(":", 1)
        computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return hmac.compare_digest(computed.hex(), h)
    except (ValueError, AttributeError):
        return False


# ═══════════════════════════════════════════════════════════════════
# JWT TOKENS (HMAC-SHA256, no external dependency)
# ═══════════════════════════════════════════════════════════════════

def create_token(user_id: int, email: str, tier: str = "free") -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "tier": tier,
        "exp": (datetime.utcnow() + timedelta(hours=settings.JWT_EXPIRATION_HOURS)).isoformat(),
        "iat": datetime.utcnow().isoformat(),
    }
    data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(settings.SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"


def decode_token(token: str) -> dict | None:
    try:
        data, sig = token.rsplit(".", 1)
        expected = hmac.new(settings.SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(data + "=="))
        if datetime.fromisoformat(payload["exp"]) < datetime.utcnow():
            return None
        return payload
    except Exception:
        return None


def generate_api_key() -> str:
    return f"cs_{secrets.token_hex(24)}"


# ═══════════════════════════════════════════════════════════════════
# FLASK DECORATORS
# ═══════════════════════════════════════════════════════════════════

def auth_required(f):
    """Authenticate via Bearer token, API key header, or query param."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        g.user_id = None
        g.user_tier = "free"

        # Try Bearer token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            payload = decode_token(auth_header[7:])
            if payload:
                g.user_id = payload["sub"]
                g.user_tier = payload.get("tier", "free")
                return f(*args, **kwargs)
            return jsonify({"error": "Invalid or expired token"}), 401

        # Try API key (header or query param)
        api_key = request.headers.get("X-API-Key") or request.args.get("access_token")
        if api_key:
            with get_db() as db:
                user = db.execute(
                    "SELECT id, tier, is_active FROM users WHERE api_key=?", (api_key,)
                ).fetchone()
                if not user:
                    return jsonify({"error": "Invalid API key"}), 401
                if not user["is_active"]:
                    return jsonify({"error": "Account disabled"}), 403
                g.user_id = user["id"]
                g.user_tier = user["tier"]
                return f(*args, **kwargs)

        # Allow unauthenticated with free tier limits
        return f(*args, **kwargs)

    return decorated


def auth_required_strict(f):
    """Require authentication — no anonymous access."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        g.user_id = None
        g.user_tier = "free"

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            payload = decode_token(auth_header[7:])
            if payload:
                g.user_id = payload["sub"]
                g.user_tier = payload.get("tier", "free")
                return f(*args, **kwargs)

        api_key = request.headers.get("X-API-Key") or request.args.get("access_token")
        if api_key:
            with get_db() as db:
                user = db.execute("SELECT id, tier FROM users WHERE api_key=? AND is_active=1", (api_key,)).fetchone()
                if user:
                    g.user_id = user["id"]
                    g.user_tier = user["tier"]
                    return f(*args, **kwargs)

        return jsonify({"error": "Authentication required"}), 401

    return decorated


def rate_limit(f):
    """Apply tier-based rate limiting."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not g.get("user_id"):
            # Anonymous: very limited
            return f(*args, **kwargs)

        with get_db() as db:
            user = db.execute(
                "SELECT tier, queries_today, queries_reset_at FROM users WHERE id=?",
                (g.user_id,)
            ).fetchone()

            if user:
                limit = settings.rate_limits.get(user["tier"], 100)
                reset_at = user["queries_reset_at"]

                # Reset daily counter if needed
                if reset_at and datetime.fromisoformat(reset_at) < datetime.utcnow():
                    db.execute(
                        "UPDATE users SET queries_today=1, queries_reset_at=? WHERE id=?",
                        ((datetime.utcnow() + timedelta(days=1)).isoformat(), g.user_id),
                    )
                elif user["queries_today"] >= limit:
                    return jsonify({
                        "error": "Rate limit exceeded",
                        "limit": limit,
                        "tier": user["tier"],
                        "reset_at": reset_at,
                    }), 429
                else:
                    db.execute("UPDATE users SET queries_today=queries_today+1 WHERE id=?", (g.user_id,))

        return f(*args, **kwargs)

    return decorated
