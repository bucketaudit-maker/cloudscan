# ☁ CloudScan — Open Cloud Storage Search Engine

A production-grade, full-stack application for discovering and searching publicly accessible cloud storage buckets across all major providers. Real-time scan streaming via Server-Sent Events.

![Python](https://img.shields.io/badge/Python-3.12-blue) ![Flask](https://img.shields.io/badge/Flask-3.1-green) ![React](https://img.shields.io/badge/React-18-61dafb) ![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue) ![License](https://img.shields.io/badge/License-MIT-yellow)

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                    React + TypeScript Frontend                     │
│  Home │ File Search │ Bucket Browser │ Live Scanner │ API Docs     │
│  Real-time SSE scan streaming │ Responsive │ Vite + HMR            │
└───────────────────────┬───────────────────────────────────────────┘
                        │ HTTP REST + SSE (Server-Sent Events)
┌───────────────────────┴───────────────────────────────────────────┐
│                     Flask API Server (Gunicorn)                    │
│  /files (FTS5 search) │ /buckets │ /stats │ /scans │ /auth        │
│  JWT + API Key Auth │ Tiered Rate Limiting │ SSE Event Stream      │
└───────────────────────┬───────────────────────────────────────────┘
                        │
┌───────────────────────┴───────────────────────────────────────────┐
│               SQLite + FTS5 Full-Text Search Engine                │
│  Porter stemming │ Boolean queries │ Extension/size filtering      │
│  Triggers for auto FTS sync │ WAL mode for concurrent access       │
└───────────────────────┬───────────────────────────────────────────┘
                        │
┌───────────────────────┴───────────────────────────────────────────┐
│             Async Multi-Provider Scanner Engine                     │
│  AWS S3 │ Azure Blob │ GCP Storage │ DO Spaces │ Alibaba OSS      │
│  50+ concurrent probes │ XML listing parser │ Pagination           │
│  Name generation: keywords, company patterns, brute-force          │
└───────────────────────────────────────────────────────────────────┘
```

## Features

### 🔍 Multi-Provider Bucket Discovery
- **5 providers**: AWS S3, Azure Blob, GCP Storage, DigitalOcean Spaces, Alibaba Cloud OSS
- **Smart name generation**: Keyword permutations, company name patterns, common conventions
- **Async scanning**: 50+ concurrent HTTP probes with configurable parallelism
- **Status detection**: Open (listable), Closed (403), Partial, Not Found

### 📡 Real-Time Scan Streaming
- **Server-Sent Events (SSE)**: Live progress, bucket discoveries, and file counts
- **Live dashboard**: Watch buckets appear in real-time as they're discovered
- **Progress tracking**: Names checked, buckets found, files indexed, errors

### 🔎 Full-Text File Search
- **FTS5 engine**: Porter stemming, Unicode support, boolean queries (AND, NOT)
- **Filters**: Extension, provider, bucket name, file size range
- **Sort**: Relevance, size, date, filename
- **Pagination**: Up to 200 results per page

### 🔐 Auth & Rate Limiting
- **JWT tokens** + **API keys** (header or query param)
- **Tiered rate limits**: Free (100/day), Premium (5K/day), Enterprise (50K/day)
- **PBKDF2 password hashing**

### 🐳 Production Ready
- **Docker Compose**: One command to run everything
- **Gunicorn**: Multi-worker production server with thread support for SSE
- **GitHub Actions CI**: Lint, test, type-check, build
- **Comprehensive tests**: API, auth, database, search

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- (Optional) Docker & Docker Compose

### Option 1: Local Development

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/cloudscan.git
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
git clone https://github.com/YOUR_USERNAME/cloudscan.git
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

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/api/v1/health` | Health check | No |
| `GET` | `/api/v1/stats` | Database statistics | No |
| `GET` | `/api/v1/providers` | List cloud providers | No |
| `GET` | `/api/v1/files?q=...` | Full-text file search | Optional |
| `GET` | `/api/v1/files/random` | Random interesting files | Optional |
| `GET` | `/api/v1/buckets` | List buckets | Optional |
| `GET` | `/api/v1/buckets/:id` | Bucket detail + files | Optional |
| `POST` | `/api/v1/scans` | Start discovery scan | Required |
| `GET` | `/api/v1/scans/:id` | Scan job status | Required |
| `GET` | `/api/v1/events/scans` | SSE real-time stream | No |
| `POST` | `/api/v1/auth/register` | Create account | No |
| `POST` | `/api/v1/auth/login` | Login | No |

### Search Parameters
| Param | Description | Example |
|-------|-------------|---------|
| `q` | Full-text query (supports NOT) | `backup -test` |
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
├── README.md
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt         # Pinned Python dependencies
│   ├── app/
│   │   ├── main.py              # Flask app factory + entry point
│   │   ├── config.py            # Centralized settings from env
│   │   ├── seed.py              # Demo data seeder
│   │   ├── api/
│   │   │   └── routes.py        # All REST endpoints + SSE streaming
│   │   ├── models/
│   │   │   └── database.py      # SQLite + FTS5 schema, DAL
│   │   ├── scanners/
│   │   │   └── engine.py        # Async multi-provider scanner
│   │   ├── services/
│   │   │   └── scan_service.py  # Scan orchestration + event bridge
│   │   └── utils/
│   │       └── auth.py          # JWT, API keys, password hashing
│   └── tests/
│       └── test_api.py          # Comprehensive test suite
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
        ├── App.tsx              # Full application (all views)
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
| Database | SQLite + FTS5 | PostgreSQL + pg_trgm or Elasticsearch |
| Cache | None | Redis for rate limiting + search cache |
| Workers | Flask dev server | Gunicorn (4 workers, 4 threads) |
| Scanner | Single process | Celery distributed workers |
| Queue | In-process | Redis / RabbitMQ |
| Frontend | Vite dev server | Nginx + CDN |
| Monitoring | Logging | Prometheus + Grafana |
| Auth | HMAC JWT | RS256 JWT or Auth0 |

---

## Disclaimer

This tool is intended for **security research and educational purposes only**. Always ensure you have proper authorization before scanning cloud infrastructure. Unauthorized access to cloud storage is illegal in most jurisdictions.

## License

MIT
