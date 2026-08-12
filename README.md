# ☁ BucketAudit — Cloud Storage Security Platform

A production-grade, full-stack platform for discovering, searching, and continuously monitoring publicly accessible cloud storage buckets across all major providers. Includes AI-powered analysis, real-time scan streaming, compliance reporting, team collaboration, and automated remediation tracking.

![Python](https://img.shields.io/badge/Python-3.12-blue) ![Flask](https://img.shields.io/badge/Flask-3.1-green) ![React](https://img.shields.io/badge/React-18-61dafb) ![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue) ![License](https://img.shields.io/badge/License-MIT-yellow)

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                      React + TypeScript Frontend (Vite)                     │
│  Home │ File Search │ Bucket Browser │ Live Scanner │ Monitoring │ Alerts   │
│  AI Insights │ Compliance │ Drift Detection │ Remediation │ Dashboard      │
│  Settings │ Org Management │ Rules │ Activity Log │ API Docs │ Pricing     │
│  Real-time SSE streaming │ Responsive SPA │ HMR in dev                     │
└───────────────────────┬────────────────────────────────────────────────────┘
                        │ HTTP REST + SSE (Server-Sent Events)
┌───────────────────────┴────────────────────────────────────────────────────┐
│                      Flask API Server (Gunicorn) — 80+ Endpoints           │
│  /files (FTS5/tsvector search) │ /buckets │ /scans │ /monitor │ /ai       │
│  /auth (JWT + API Key + 2FA) │ /orgs │ /reports │ /drift │ /alert-rules   │
│  CSRF Protection │ Tiered Rate Limiting │ Audit Logging │ SSE Stream      │
│  Webhooks │ Notifications │ Scheduled Scans │ Remediation Tracking        │
└───────────────────────┬────────────────────────────────────────────────────┘
                        │
┌───────────────────────┴────────────────────────────────────────────────────┐
│              PostgreSQL (prod) / SQLite + FTS5 (dev)                        │
│  30+ tables │ Alembic migrations │ Full-text search │ Audit trail          │
│  WAL mode (SQLite) │ tsvector + GIN indexes (PostgreSQL)                   │
└───────────────────────┬────────────────────────────────────────────────────┘
                        │
┌───────────────────────┴────────────────────────────────────────────────────┐
│              Async Multi-Provider Scanner Engine                            │
│  AWS S3 │ Azure Blob │ GCP Storage │ DO Spaces │ Alibaba OSS              │
│  50+ concurrent probes │ XML listing parser │ Pagination                   │
│  Name generation: keywords, company patterns, brute-force                  │
└────────────────────────────────────────────────────────────────────────────┘
```

## Features

### 🔍 Multi-Provider Bucket Discovery
- **5 providers**: AWS S3, Azure Blob, GCP Storage, DigitalOcean Spaces, Alibaba Cloud OSS
- **Smart name generation**: Keyword permutations, company name patterns, common conventions
- **Async scanning**: 50+ concurrent HTTP probes with configurable parallelism
- **Status detection**: Open (listable), Closed (403), Partial, Not Found, Error

### 📡 Real-Time Scan Streaming
- **Server-Sent Events (SSE)**: Live progress, bucket discoveries, and file counts
- **Live dashboard**: Watch buckets appear in real-time as they're discovered
- **Progress tracking**: Names checked, buckets found, files indexed, errors, elapsed time
- **Monitor events**: Watchlist scan progress and completion events

### 🔎 Full-Text File Search
- **FTS5 engine** (SQLite) / **tsvector + GIN** (PostgreSQL): Porter stemming, Unicode, boolean queries (AND, NOT)
- **Regex search**: Search by filepath patterns
- **Filters**: Extension (include/exclude), provider, bucket name, file size range, content type, date range
- **Sort**: Relevance, size (asc/desc), date (newest/oldest), filename
- **Pagination**: Up to 200 results per page with response time metrics
- **Export**: Download results as CSV, JSON, PDF, or SARIF
- **File preview**: Preview first 4KB of text files (30+ supported extensions)
- **Saved searches**: Save and reuse complex search queries

### 🛡️ Attack Surface Monitoring
- **Watchlists**: Define keyword/company sets for continuous monitoring
- **Configurable intervals**: Hourly, daily, weekly, or monthly scans
- **Alerts**: Automatic alert generation for new buckets, status changes, new files, and sensitive file detection
- **Alert severity**: Critical, high, medium, low, info — with read/resolve tracking
- **Bulk operations**: Bulk read, bulk resolve alerts
- **Monitor dashboard**: Consolidated view of watchlists, monitored assets, and alert metrics

### 🤖 AI-Powered Analysis
- **Multi-provider**: Anthropic Claude, OpenAI GPT, Google Gemini, Ollama (local)
- **File classification**: 8 sensitivity categories (credentials, PII, financial, medical, infrastructure, source code, database, generic)
- **Risk scoring**: AI-computed 0–100 risk score per bucket with severity levels
- **Natural language search**: Convert human queries like "find large SQL files in AWS" to structured search
- **Security reports**: AI-generated comprehensive security assessments
- **Keyword suggestions**: ML-powered keyword recommendations for targeted scanning
- **Alert prioritization**: AI-ranked alert priority scoring
- **Graceful degradation**: Works without AI; falls back to rule-based analysis

### 🔐 Authentication & Security
- **JWT tokens** (24h expiry) + **API keys** (header or query param)
- **Two-factor authentication (2FA)**: TOTP setup, confirm, verify, and disable
- **Password management**: Forgot password, reset with token (1h expiry)
- **CSRF protection**: Single-use tokens for all state-changing requests
- **PBKDF2 password hashing**
- **Tiered rate limits**: Free (100/day), Premium (5K/day), Enterprise (50K/day)
- **Security headers**: X-Content-Type-Options, X-Frame-Options, CSP, Permissions-Policy
- **SSRF protection**: Input validation on all URL inputs
- **Audit logging**: Complete trail of user actions with IP and user agent

### 👥 Team & Organization Management
- **Organizations**: Create workspaces for team collaboration
- **Roles**: Owner, Admin, Member, Viewer with granular permissions
- **Invitations**: Invite users by email, accept/decline invites
- **Context switching**: Switch between personal and organization contexts

### 📊 Dashboards & Analytics
- **Executive dashboard**: High-level risk metrics, trends, and remediation SLA tracking
- **Statistics**: Total files, buckets, open buckets, size, provider breakdown
- **Timeline**: Time-series charts of bucket/file discovery trends
- **Breakdown**: Risk distribution, provider distribution, classification distribution
- **Real-time counters**: Live scan progress with elapsed time

### 📋 Reports & Compliance
- **Report types**: Security, compliance, and executive summary reports
- **Formats**: JSON, HTML, PDF, SARIF (for SIEM integration)
- **Compliance frameworks**: CIS, PCI-DSS, HIPAA, SOC2 — with control mapping
- **Compliance status**: Pass, fail, partial, not applicable — per control
- **Scheduled reports**: Daily, weekly, monthly auto-generation
- **Evidence collection**: Compliance documentation and evidence tracking

### 🔄 Drift Detection & Config Tracking
- **Snapshot comparisons**: Detect changes between scans (new buckets, status changes, file deltas)
- **Change history**: Per-bucket timeline of configuration changes
- **Diff review**: Mark diffs as reviewed; classify change severity
- **Scan-level diffs**: View all changes from a specific scan job

### ⚡ Custom Alert Rules & Automation
- **Rule builder**: Define conditions on file patterns, classifications, severity, size
- **Actions**: Trigger alerts, webhooks, or notifications when rules match
- **Testing**: Test rules against sample data before activating
- **Statistics**: Track match counts and last matched timestamps

### 🔗 Webhooks & Integrations
- **Webhooks**: Custom HTTP endpoints with HMAC-SHA256 signing
- **Event filtering**: Filter by severity level
- **Slack integration**: Native Slack webhook notifications with test support
- **JIRA integration**: Create tickets from alerts
- **Failure handling**: Auto-disable after 10 consecutive delivery failures

### 🔔 Notifications
- **In-app notifications**: Real-time notification feed with unread counts
- **Slack direct messaging**: Alert delivery to Slack channels
- **Preferences**: Per-channel configuration with minimum severity thresholds
- **Notification types**: Alerts, scan completion, org invites, system notifications

### 🗓️ Scan Scheduling
- **Recurring scans**: Hourly, daily, weekly, monthly, or custom cron expressions
- **Per-schedule config**: Keywords, companies, providers per schedule
- **Manual trigger**: Run any scheduled scan on demand
- **Status tracking**: Last run, next scheduled, enable/disable toggle

### 🔧 Remediation Tracking
- **Remediation tickets**: Track bucket remediation (close bucket, remove sensitive files)
- **Assignment**: Assign to team members with priority levels
- **Status workflow**: Open → In Progress → Verified → Closed
- **Due dates**: Track remediation deadlines and completion
- **Bulk operations**: Bulk status updates, assignments, and closure

### 📝 Audit & Activity Logging
- **Activity feed**: Complete user activity history
- **Audit log**: Entity-level audit trail with timestamps, IPs, and user agents
- **Request logging**: API request/response time metrics

### 🏷️ Bookmarks & Tags
- **Bookmarks**: Save buckets and files for quick access
- **Tags**: Color-coded tags for bucket categorization and organization
- **Bookmark status**: Quick check if items are bookmarked

### 💰 Pricing & Tier Management
- **Free tier**: 100 API req/day, 3 scans/day, 1 schedule, 10 keywords
- **Premium tier**: 5K API req/day, 50 scans/day, 10 schedules, 100 keywords, AI enabled
- **Enterprise tier**: 50K+ API req/day, unlimited scans/schedules, unlimited keywords, AI enabled
- **Self-serve upgrade**: In-app tier upgrade flow

### 🐳 Production Ready
- **Docker Compose**: One command to run everything
- **PostgreSQL**: Production database with Alembic migrations
- **Gunicorn**: Multi-worker production server with thread support for SSE
- **GitHub Actions CI**: Lint, test, type-check, build
- **Comprehensive tests**: API, auth, database, search
- **OpenAPI/Swagger**: Interactive API documentation at `/api/docs`

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL 14+ (production) or SQLite (development)
- (Optional) Docker & Docker Compose

### Option 1: Local Development

```bash
# 1. Clone the repo
git clone https://github.com/bucketaudit-maker/cloudscan.git
cd cloudscan

# 2. Set up environment
cp .env.example .env

# 3. Install backend dependencies
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 4. Initialize database and seed demo data
cd ..
python -m backend.app.seed

# 5. Start the backend API server
python -m backend.app.main
# → API running at http://localhost:8000

# 6. In a NEW terminal — install and start frontend
cd frontend
npm install
npm run dev
# → UI running at http://localhost:5173
```

### Option 2: Docker Compose

```bash
git clone https://github.com/bucketaudit-maker/cloudscan.git
cd cloudscan
cp .env.example .env

# Build and start everything
docker compose up -d --build

# Seed demo data
docker compose exec backend python -m backend.app.seed

# → UI at http://localhost
# → API at http://localhost:8000
```

### Option 3: Makefile shortcuts

```bash
make install     # Install all deps
make seed        # Seed demo data
make dev-backend # Start API server
make dev-frontend # Start frontend
make docker-up   # Docker start
make test        # Run tests
```

---

## Running a Real Scan

### Via the Web UI
1. Go to the **Scanner** tab
2. Enter keywords (e.g., `backup, database, config, credentials`)
3. Optionally enter company names and select providers
4. Click **START DISCOVERY SCAN**
5. Watch results stream in real-time!

### Via the CLI
```bash
# Basic keyword scan
python -m backend.app.scanners.engine -k backup database config -n 500

# Target specific companies
python -m backend.app.scanners.engine -k secrets -c "acme-corp" "globex" -p aws gcp -n 2000

# Full scan across all providers
python -m backend.app.scanners.engine -k backup credentials terraform .env -n 5000
```

### Via the API
```bash
# Register to get an API key
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","username":"you","password":"securepass123"}'

# Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keywords":["backup","credentials"],"providers":["aws","gcp"]}'

# Stream real-time results (SSE)
curl -N http://localhost:8000/api/v1/events/scans
```

---

## API Reference

BucketAudit exposes **80+ REST API endpoints**. See [`API.md`](./API.md) for the full reference with request/response examples.

### Core Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/api/v1/health` | Health check | No |
| `GET` | `/api/v1/stats` | Database statistics | No |
| `GET` | `/api/v1/providers` | List cloud providers | No |
| `GET` | `/api/v1/files?q=...` | Full-text file search | Optional |
| `GET` | `/api/v1/files/random` | Random interesting files | Optional |
| `GET` | `/api/v1/files/export` | Export search results (CSV/JSON/PDF/SARIF) | Optional |
| `GET` | `/api/v1/files/:id/preview` | Preview file content | Optional |
| `GET` | `/api/v1/buckets` | List buckets | Optional |
| `GET` | `/api/v1/buckets/:id` | Bucket detail + files | Optional |
| `POST` | `/api/v1/scans` | Start discovery scan | Required |
| `GET` | `/api/v1/scans/:id` | Scan job status | Required |
| `POST` | `/api/v1/scans/:id/cancel` | Cancel running scan | Required |
| `GET` | `/api/v1/events/scans` | SSE real-time stream | No |

### Authentication & 2FA

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/auth/register` | Create account | No |
| `POST` | `/api/v1/auth/login` | Login (supports 2FA) | No |
| `GET` | `/api/v1/auth/me` | Current user profile | Required |
| `POST` | `/api/v1/auth/forgot-password` | Request password reset | No |
| `POST` | `/api/v1/auth/reset-password` | Reset password with token | No |
| `POST` | `/api/v1/auth/rotate-key` | Regenerate API key | Required |
| `PUT` | `/api/v1/auth/settings` | Update profile/password | Required |
| `POST` | `/api/v1/auth/2fa/setup` | Initialize 2FA | Required |
| `POST` | `/api/v1/auth/2fa/confirm` | Confirm 2FA enrollment | Required |
| `POST` | `/api/v1/auth/2fa/verify` | Verify 2FA code on login | No |
| `POST` | `/api/v1/auth/2fa/disable` | Disable 2FA | Required |

### Monitoring & Alerts

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/monitor/watchlists` | Create watchlist | Required |
| `GET` | `/api/v1/monitor/watchlists` | List watchlists | Required |
| `POST` | `/api/v1/monitor/watchlists/:id/scan` | Trigger watchlist scan | Required |
| `GET` | `/api/v1/monitor/alerts` | List alerts (filter by severity/unread) | Required |
| `POST` | `/api/v1/monitor/alerts/:id/resolve` | Resolve alert | Required |
| `POST` | `/api/v1/monitor/alerts/bulk-resolve` | Bulk resolve alerts | Required |
| `GET` | `/api/v1/monitor/dashboard` | Monitoring summary | Required |

### AI Features

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/api/v1/ai/status` | AI provider status | No |
| `POST` | `/api/v1/ai/provider` | Switch AI provider | Required |
| `POST` | `/api/v1/ai/classify/:bucket_id` | Classify bucket files | Required |
| `POST` | `/api/v1/ai/risk/:bucket_id` | Compute risk score | Required |
| `POST` | `/api/v1/ai/search` | Natural language search | Required |
| `POST` | `/api/v1/ai/report` | Generate security report | Required |
| `POST` | `/api/v1/ai/suggest-keywords` | AI keyword suggestions | Required |
| `POST` | `/api/v1/ai/prioritize-alerts` | AI alert prioritization | Required |

### Webhooks, Notifications & Integrations

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/monitor/webhooks` | Create webhook | Required |
| `POST` | `/api/v1/monitor/webhooks/:id/test` | Test webhook delivery | Required |
| `GET` | `/api/v1/notifications` | Get notifications | Required |
| `GET` | `/api/v1/notifications/unread-count` | Unread notification count | Required |
| `POST` | `/api/v1/notifications/slack` | Configure Slack integration | Required |
| `POST` | `/api/v1/notifications/slack/test` | Test Slack integration | Required |

### Organizations, Reports & More

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/orgs` | Create organization | Required |
| `POST` | `/api/v1/orgs/:id/invite` | Invite team member | Required |
| `POST` | `/api/v1/reports/generate` | Generate report (security/compliance/executive) | Required |
| `GET` | `/api/v1/reports` | List reports | Required |
| `GET` | `/api/v1/drift/diffs` | List configuration diffs | Required |
| `POST` | `/api/v1/alert-rules` | Create custom alert rule | Required |
| `GET` | `/api/v1/scans/schedules` | List scan schedules | Required |
| `GET` | `/api/v1/activity` | User activity feed | Required |
| `GET` | `/api/v1/audit-log` | Audit log | Required |
| `GET` | `/api/v1/dashboard/executive` | Executive dashboard | Required |
| `GET` | `/api/v1/csrf-token` | Get CSRF token | No |

### Search Parameters

| Param | Description | Example |
|-------|-------------|---------|
| `q` | Full-text query (supports NOT) | `backup -test` |
| `regex` | Regex pattern for filepath matching | `.*credentials.*\.json` |
| `ext` | Filter by extensions (comma-sep) | `sql,csv,json` |
| `exclude_ext` | Exclude extensions | `log,txt` |
| `provider` | Filter by provider | `aws` |
| `bucket` | Filter by bucket name | `prod` |
| `min_size` / `max_size` | File size range (bytes) | `1024` |
| `sort` | Sort order | `relevance,size_desc,newest` |
| `page` / `per_page` | Pagination | `1` / `50` |

---

## Project Structure

```
cloudscan/
├── .github/workflows/ci.yml    # GitHub Actions CI pipeline
├── .env.example                 # Environment configuration template
├── .gitignore
├── docker-compose.yml           # Full-stack Docker orchestration
├── Makefile                     # Development shortcuts
├── README.md                    # This file
├── API.md                       # Full API reference (80+ endpoints)
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt         # Pinned Python dependencies
│   ├── alembic.ini              # Alembic migration config
│   ├── alembic/                 # Database migration versions
│   ├── app/
│   │   ├── main.py              # Flask app factory + entry point
│   │   ├── config.py            # Centralized settings from env
│   │   ├── seed.py              # Demo data seeder
│   │   ├── api/
│   │   │   └── routes.py        # All REST endpoints + SSE streaming (80+)
│   │   ├── models/
│   │   │   └── database.py      # DB schema, stores, dual SQLite/Postgres support
│   │   ├── scanners/
│   │   │   └── engine.py        # Async multi-provider scanner
│   │   ├── services/
│   │   │   ├── scan_service.py  # Scan orchestration + event bridge
│   │   │   ├── monitor_service.py # Watchlist monitoring + alert generation
│   │   │   └── ai_service.py    # Multi-provider AI integration
│   │   ├── workers/
│   │   │   └── monitor_scheduler.py # Background monitoring scheduler
│   │   └── utils/
│   │       └── auth.py          # JWT, API keys, password hashing, 2FA
│   └── tests/
│       └── test_api.py          # Comprehensive test suite
│
├── docs/
│   ├── API.md                   # Quick API overview
│   ├── DEPLOYMENT.md            # Production deployment guide
│   ├── POSTGRES_AND_MIGRATIONS.md # Database migration plan
│   └── SCANNER.md               # Scanner engine architecture
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf               # Production reverse proxy config
    ├── package.json
    ├── tsconfig.json
    ├── vite.config.ts           # Vite with API proxy
    ├── index.html
    └── src/
        ├── main.tsx             # React entry point
        ├── App.tsx              # Full application (18 views, all-in-one SPA)
        ├── index.css            # Design system + CSS variables
        └── lib/
            ├── api.ts           # API client + SSE subscription
            └── utils.ts         # Formatters, constants, icons
```

---

## Production Scaling Notes

For high-traffic production deployment:

| Component | Development | Production |
|-----------|------------|------------|
| Database | SQLite + FTS5 | PostgreSQL + tsvector/GIN or Elasticsearch |
| Cache | None | Redis for rate limiting + search cache |
| Workers | Flask dev server | Gunicorn (4 workers, 4 threads) |
| Scanner | Single process | Celery distributed workers |
| Queue | In-process | Redis / RabbitMQ |
| Frontend | Vite dev server | Nginx + CDN |
| Monitoring | Logging | Prometheus + Grafana |
| Auth | HMAC JWT | RS256 JWT or Auth0 |
| AI | Single provider | Multi-provider failover |

---

## Documentation

| Document | Description |
|----------|-------------|
| [`API.md`](./API.md) | Full REST API reference (80+ endpoints with examples) |
| [`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md) | Production deployment guide (Docker, VPS, systemd) |
| [`docs/SCANNER.md`](./docs/SCANNER.md) | Scanner engine architecture and internals |
| [`docs/POSTGRES_AND_MIGRATIONS.md`](./docs/POSTGRES_AND_MIGRATIONS.md) | Database migration plan (SQLite → PostgreSQL) |

---

## Disclaimer

This tool is intended for **security research and educational purposes only**. Always ensure you have proper authorization before scanning cloud infrastructure. Unauthorized access to cloud storage is illegal in most jurisdictions.

## License

MIT
