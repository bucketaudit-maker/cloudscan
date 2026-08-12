# BucketAudit — Deployment Guide

## Overview

BucketAudit consists of several components:
- **API Server**: Flask REST API (80+ endpoints) serving the backend logic
- **Frontend**: React SPA served via Nginx or Vite dev server
- **Database**: PostgreSQL (production) or SQLite (development)
- **Monitor Worker**: Background scheduler for watchlist scans and alert generation
- **AI Provider**: Optional connection to Anthropic, OpenAI, Google Gemini, or Ollama

## Managed Hosting (Railway)

For a first private beta without managing a server, use the service-by-service
[Railway deployment guide](RAILWAY.md). It deploys PostgreSQL, the API, the
dedicated scheduler worker, and the frontend separately and keeps internal
services off the public internet.

## Database (PostgreSQL)

BucketAudit uses **PostgreSQL** by default for both local and production. SQLite is only used when `DATABASE_URL` is set to a `sqlite:///` URL (e.g. in tests).

- **Local**: You can keep `RUN_DB_MIGRATIONS_ON_STARTUP=true` for convenience.
- **Production**: Set `RUN_DB_MIGRATIONS_ON_STARTUP=false` and run migrations as an explicit deploy step (`alembic upgrade head`).
- **Manual**: Create a database, set `DATABASE_URL`, run `cd backend && alembic upgrade head`, then start the API.
- **Schema**: 30+ tables covering users, buckets, files, scans, watchlists, alerts, organizations, compliance, drift detection, remediations, notifications, webhooks, audit logs, and more.

## Environment URLs (Local vs Production)

- **Local**: No `VITE_API_URL` needed. The frontend uses relative `/api/v1`; Vite’s dev server proxies to `http://localhost:8000`. Backend `CORS_ORIGINS` can stay as `http://localhost:5173,http://localhost:3000`.
- **Production (same host)**: If the UI and API are served from the same domain, leave `VITE_API_URL` unset so the app keeps using relative `/api/v1`. Set `CORS_ORIGINS=https://bucketaudit.com`.
- **Production (separate API host)**: Build the frontend with `VITE_API_URL=https://api.bucketaudit.com` so all requests and SSE go to the API host. Set `CORS_ORIGINS=https://app.bucketaudit.com` on the backend.

## Docker Compose (Recommended)

The fastest way to deploy BucketAudit in production.

### Prerequisites
- Docker Engine 20+
- Docker Compose v2+
- 1GB RAM minimum

### Steps

```bash
# 1. Clone and configure
git clone https://github.com/bucketaudit-maker/cloudscan.git
cd cloudscan
cp .env.example .env

# 2. Edit .env for production
#    - Set APP_ENV=production
#    - Set a strong SECRET_KEY
#    - Set DEBUG=false
#    - Adjust CORS_ORIGINS to your domain
#    - Set RUN_DB_MIGRATIONS_ON_STARTUP=false
#    - Set ENABLE_MONITOR_SCHEDULER=false on API containers
#    - Configure AI provider (optional): ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.
#    - Configure Slack webhook URL for notifications (optional)

# 3. Build and start
docker compose up -d --build

# 4. Seed initial data (optional)
docker compose exec backend python -m backend.app.seed

# 5. Verify
curl http://localhost/api/v1/health
```

### SSL with Nginx Reverse Proxy

For HTTPS, add an nginx reverse proxy in front:

```nginx
server {
    listen 443 ssl;
    server_name app.bucketaudit.com;

    ssl_certificate /etc/letsencrypt/live/app.bucketaudit.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.bucketaudit.com/privkey.pem;

    location / {
        proxy_pass http://localhost:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }
}
```

---

## Manual Deployment (VPS / Bare Metal)

### Backend

```bash
# Install system dependencies
sudo apt update && sudo apt install -y python3.12 python3.12-venv

# Setup
cd cloudscan/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize
cd ..
cd backend && alembic upgrade head && cd ..
python -m backend.app.seed

# Run with Gunicorn (production WSGI)
gunicorn backend.app.main:app \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --threads 4 \
    --timeout 120 \
    --keep-alive 65 \
    --access-logfile /var/log/cloudscan/access.log \
    --error-logfile /var/log/cloudscan/error.log
```

### Dedicated Monitor Worker

Run scheduler in a dedicated process (not in the API process):

```bash
export ENABLE_MONITOR_SCHEDULER=true
export RUN_DB_MIGRATIONS_ON_STARTUP=false
python -m backend.app.workers.monitor_scheduler
```

### Systemd Service

Create `/etc/systemd/system/cloudscan-api.service`:

```ini
[Unit]
Description=BucketAudit API Server
After=network.target

[Service]
Type=simple
User=cloudscan
Group=cloudscan
WorkingDirectory=/opt/cloudscan
Environment=PATH=/opt/cloudscan/backend/venv/bin:/usr/bin
Environment=PYTHONPATH=/opt/cloudscan
EnvironmentFile=/opt/cloudscan/.env
ExecStart=/opt/cloudscan/backend/venv/bin/gunicorn backend.app.main:app \
    --bind 0.0.0.0:8000 \
    --workers 4 --threads 4 \
    --timeout 120 --keep-alive 65
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/cloudscan-monitor.service`:

```ini
[Unit]
Description=BucketAudit Monitor Scheduler
After=network.target

[Service]
Type=simple
User=cloudscan
Group=cloudscan
WorkingDirectory=/opt/cloudscan
Environment=PATH=/opt/cloudscan/backend/venv/bin:/usr/bin
Environment=PYTHONPATH=/opt/cloudscan
EnvironmentFile=/opt/cloudscan/.env
Environment=ENABLE_MONITOR_SCHEDULER=true
Environment=RUN_DB_MIGRATIONS_ON_STARTUP=false
ExecStart=/opt/cloudscan/backend/venv/bin/python -m backend.app.workers.monitor_scheduler
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable cloudscan-api
sudo systemctl start cloudscan-api
sudo systemctl enable cloudscan-monitor
sudo systemctl start cloudscan-monitor
```

### Frontend

```bash
cd frontend
npm install
npm run build

# Serve the dist/ folder with any static file server:
# - Nginx (see docker nginx.conf for reference)
# - Caddy: caddy file-server --root dist --listen :80
# - Node: npx serve dist -l 80
```

---

## Scheduled Scanning

Set up a cron job to run periodic scans:

```bash
# Every 6 hours, scan common keywords
0 */6 * * * cd /opt/cloudscan && ./scripts/scan.sh -k "backup,database,credentials,secret,config" -n 2000

# Daily company-targeted scan
0 2 * * * cd /opt/cloudscan && ./scripts/scan.sh -k "internal,private" -c "target-company" -n 5000

# Weekly database backup
0 3 * * 0 cd /opt/cloudscan && ./scripts/db.sh backup
```

---

## Scaling Considerations

### Database

For > 1M files, migrate from SQLite to PostgreSQL:

```bash
# .env
DATABASE_URL=postgresql://user:pass@db:5432/cloudscan
```

The schema is compatible — swap the connection layer in `database.py`.

For full-text search at scale, consider Elasticsearch or Meilisearch alongside PostgreSQL.

### Scanner Workers

For parallel scanning across multiple machines:

1. Use Redis/RabbitMQ as a job queue
2. Modify `scan_service.py` to publish scan tasks to the queue
3. Run scanner workers on multiple machines consuming from the queue

### Caching

Add Redis for:
- Rate limiting (currently in-process)
- Search result caching (LRU, 5-minute TTL)
- Session storage

```bash
# .env
REDIS_URL=redis://redis:6379/0
```

---

## Monitoring

### Healthcheck
```bash
curl http://localhost:8000/api/v1/health
```

### Database stats
```bash
./scripts/db.sh stats
```

### Docker logs
```bash
docker compose logs -f backend
```

### Recommended monitoring stack
- **Prometheus**: Scrape `/metrics` endpoint (add with flask-prometheus)
- **Grafana**: Dashboard for request rates, scan progress, DB size
- **Sentry**: Error tracking for production

---

## Security Configuration

### CSRF Protection

BucketAudit enforces CSRF tokens on all POST/PUT/DELETE requests. Clients must:
1. Fetch a token from `GET /api/v1/csrf-token`
2. Include it as `X-CSRF-Token` header on state-changing requests

Tokens are single-use and tied to the user session.

### Two-Factor Authentication (2FA)

2FA uses TOTP (Time-based One-Time Passwords). Users enable it via `/auth/2fa/setup` and `/auth/2fa/confirm`. Once enabled, login requires a 2FA code via `/auth/2fa/verify`.

### Security Headers

The API server sets the following security headers on all responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` (restrictive policy)
- `Permissions-Policy` (disables geolocation, camera, microphone)

---

## AI Provider Configuration

BucketAudit supports multiple AI providers for file classification, risk scoring, natural language search, and report generation.

| Provider | Environment Variable | Models |
|----------|---------------------|--------|
| Anthropic Claude | `ANTHROPIC_API_KEY` | claude-haiku (fast), claude-sonnet (quality) |
| OpenAI | `OPENAI_API_KEY` | GPT-3.5 (fast), GPT-4 (quality) |
| Google Gemini | `GOOGLE_API_KEY` | Gemini Pro |
| Ollama (local) | `OLLAMA_URL` | Any local model |

Set the desired API key in `.env`. Users can switch providers at runtime via `POST /ai/provider`.

---

## Webhook & Notification Setup

### Webhooks
Configure webhooks via the API or UI to receive alerts at external HTTP endpoints. Webhooks support:
- HMAC-SHA256 signature verification
- Severity-based event filtering
- Auto-disable after 10 consecutive failures

### Slack Notifications
Configure Slack integration via `POST /notifications/slack` with a webhook URL. Test delivery with `POST /notifications/slack/test`.

### Notification Preferences
Users can configure per-channel notification preferences including minimum severity thresholds via `PUT /notifications/prefs`.
