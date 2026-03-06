# CloudScan — Deployment Guide

## Database (PostgreSQL)

CloudScan uses **PostgreSQL** by default for both local and production. SQLite is only used when `DATABASE_URL` is set to a `sqlite:///` URL (e.g. in tests).

- **Local**: Start Postgres (e.g. `docker compose up -d db` or a local install), set `DATABASE_URL=postgresql://cloudscan:cloudscan@localhost:5432/cloudscan`, then start the app. Migrations run automatically on startup (`alembic upgrade head`).
- **Docker Compose**: The `db` service runs Postgres; the backend waits for it and runs migrations on start.
- **Manual**: Create a database, set `DATABASE_URL`, run `cd backend && alembic upgrade head`, then start the API.

## Environment URLs (Local vs Production)

- **Local**: No `VITE_API_URL` needed. The frontend uses relative `/api/v1`; Vite’s dev server proxies to `http://localhost:8000`. Backend `CORS_ORIGINS` can stay as `http://localhost:5173,http://localhost:3000`.
- **Production (same host)**: If the UI and API are served from the same domain (e.g. nginx serves both), leave `VITE_API_URL` unset so the app keeps using relative `/api/v1`. Set `CORS_ORIGINS` to your frontend origin(s), e.g. `https://app.yourdomain.com`.
- **Production (API on another host)**: Build the frontend with `VITE_API_URL=https://api.yourdomain.com` so all requests and SSE go to the API host. Set `CORS_ORIGINS` on the backend to include your frontend origin, e.g. `https://app.yourdomain.com`.

## Docker Compose (Recommended)

The fastest way to deploy CloudScan in production.

### Prerequisites
- Docker Engine 20+
- Docker Compose v2+
- 1GB RAM minimum

### Steps

```bash
# 1. Clone and configure
git clone https://github.com/YOUR_USERNAME/cloudscan.git
cd cloudscan
cp .env.example .env

# 2. Edit .env for production
#    - Set APP_ENV=production
#    - Set a strong SECRET_KEY
#    - Set DEBUG=false
#    - Adjust CORS_ORIGINS to your domain

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
    server_name cloudscan.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/cloudscan.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloudscan.yourdomain.com/privkey.pem;

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

### Systemd Service

Create `/etc/systemd/system/cloudscan-api.service`:

```ini
[Unit]
Description=CloudScan API Server
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

```bash
sudo systemctl enable cloudscan-api
sudo systemctl start cloudscan-api
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
