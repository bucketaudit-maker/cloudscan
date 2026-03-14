# CloudScan REST API Reference

CloudScan exposes a JSON REST API for cloud storage security scanning, file search, monitoring, and AI-powered analysis.

**Base URL:** `/api/v1`

All requests and responses use `Content-Type: application/json` unless otherwise noted. Timestamps are ISO 8601 UTC.

---

## Table of Contents

- [Authentication](#authentication)
- [Errors](#errors)
- [Health Check](#health-check)
- [Auth Endpoints](#auth-endpoints)
- [File Search](#file-search)
- [Saved Searches](#saved-searches)
- [Buckets](#buckets)
- [Statistics & Analytics](#statistics--analytics)
- [Providers](#providers)
- [Scans](#scans)
- [Real-time Events (SSE)](#real-time-events-sse)
- [Monitoring — Watchlists](#monitoring--watchlists)
- [Monitoring — Alerts](#monitoring--alerts)
- [Webhooks](#webhooks)
- [AI Features](#ai-features)
- [Data Objects](#data-objects)

---

## Authentication

Three authentication methods are supported:

| Method | Header / Param | Example |
|--------|---------------|---------|
| **Bearer Token** (JWT) | `Authorization: Bearer <token>` | Obtained from `/auth/register` or `/auth/login` |
| **API Key Header** | `X-API-Key: cs_<hex>` | Assigned on registration |
| **API Key Query Param** | `?access_token=cs_<hex>` | For SSE or browser-based access |

```bash
# Bearer token
curl -H "Authorization: Bearer eyJhbGci..." https://your-host/api/v1/files?q=backup

# API key
curl -H "X-API-Key: cs_a1b2c3d4..." https://your-host/api/v1/files?q=backup
```

### Auth Levels

Endpoints use one of two decorators:

| Level | Description |
|-------|-------------|
| `auth_required` | Allows anonymous access with free-tier rate limits. Authenticated users get higher limits. |
| `auth_required_strict` | Requires a valid token or API key. Returns `401` if missing. |

### Rate Limiting

Rate limits are enforced per-user with daily query counters. Tiers: `free`, `premium`, `enterprise`. Exceeding the limit returns `429 Too Many Requests`.

---

## Errors

All errors return a JSON body:

```json
{
  "error": "Human-readable error message"
}
```

| Status | Meaning |
|--------|---------|
| `400` | Bad request — missing or invalid parameters |
| `401` | Authentication required or invalid credentials |
| `403` | Account disabled |
| `404` | Resource not found |
| `409` | Conflict — duplicate email or username |
| `429` | Rate limit exceeded |
| `500` | Internal server error |

---

## Health Check

```
GET /health
```

**Auth:** None (public)

```bash
curl https://your-host/api/v1/health
```

**Response `200`:**

```json
{
  "status": "ok",
  "timestamp": "2025-03-10T14:00:00",
  "version": "1.0.0"
}
```

---

## Auth Endpoints

### Register

```
POST /auth/register
```

Create a new account. Returns a JWT token and API key.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User email (normalized to lowercase) |
| `username` | string | Yes | Min 3 characters |
| `password` | string | Yes | Min 8 characters |

```bash
curl -X POST https://your-host/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "username": "scanner", "password": "securepass123"}'
```

**Response `201`:**

```json
{
  "token": "eyJhbGci...",
  "api_key": "cs_a1b2c3d4e5f6...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "scanner",
    "tier": "free"
  }
}
```

**Errors:** `400` invalid fields, `409` email/username taken.

---

### Login

```
POST /auth/login
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Account email |
| `password` | string | Yes | Account password |

```bash
curl -X POST https://your-host/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepass123"}'
```

**Response `200`:**

```json
{
  "token": "eyJhbGci...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "scanner",
    "tier": "free",
    "api_key": "cs_a1b2c3d4e5f6..."
  }
}
```

**Errors:** `400` missing fields, `401` invalid credentials, `403` account disabled.

---

### Get Current User

```
GET /auth/me
```

**Auth:** `auth_required_strict`

```bash
curl -H "Authorization: Bearer eyJhbGci..." https://your-host/api/v1/auth/me
```

**Response `200`:**

```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "scanner",
  "tier": "free",
  "api_key": "cs_a1b2c3d4e5f6...",
  "created_at": "2025-01-15T10:30:00",
  "last_login": "2025-03-10T14:22:00",
  "queries_today": 42
}
```

---

### Forgot Password

```
POST /auth/forgot-password
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Account email |

**Response `200`:**

```json
{
  "message": "If that email exists, a reset link has been generated",
  "token": "reset_token_string",
  "expires_in": "1 hour",
  "reset_url": "/reset-password?token=reset_token_string"
}
```

---

### Reset Password

```
POST /auth/reset-password
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | Yes | Reset token from forgot-password |
| `password` | string | Yes | New password (min 8 chars) |

**Response `200`:**

```json
{
  "message": "Password reset successfully",
  "token": "new_jwt_token"
}
```

**Errors:** `400` invalid/expired token, password too short.

---

## File Search

### Search Files

```
GET /files
```

Full-text and regex file search with filtering and pagination.

**Auth:** `auth_required` — **Rate limited**

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `q` | string | — | Search query (full-text) |
| `regex` | string | — | Regex pattern for filepath matching (alternative to `q`) |
| `ext` | string | — | Comma-separated extensions to include (e.g. `pdf,doc,xlsx`) |
| `exclude_ext` | string | — | Comma-separated extensions to exclude |
| `provider` | string | — | Filter by provider: `aws`, `azure`, `gcp`, `digitalocean`, `alibaba` |
| `bucket` | string | — | Filter by bucket name |
| `sort` | string | `relevance` | Sort order: `relevance`, `size_asc`, `size_desc`, `newest`, `oldest`, `filename` |
| `page` | integer | `1` | Page number |
| `per_page` | integer | `50` | Results per page (max `200`) |
| `min_size` | integer | — | Minimum file size in bytes |
| `max_size` | integer | — | Maximum file size in bytes |

```bash
# Full-text search
curl -H "X-API-Key: cs_..." "https://your-host/api/v1/files?q=database+backup&ext=sql,bak&sort=newest"

# Regex search
curl -H "X-API-Key: cs_..." "https://your-host/api/v1/files?regex=.*credentials.*\.json"
```

**Response `200`:**

```json
{
  "items": [
    {
      "id": 1234,
      "filepath": "backups/prod-db-2025.sql",
      "filename": "prod-db-2025.sql",
      "extension": "sql",
      "size_bytes": 52428800,
      "url": "https://bucket-name.s3.amazonaws.com/backups/prod-db-2025.sql",
      "bucket_name": "bucket-name",
      "bucket_url": "https://bucket-name.s3.amazonaws.com",
      "region": "us-east-1",
      "provider_name": "aws",
      "provider_display": "Amazon S3",
      "ai_classification": "database",
      "last_modified": "2025-03-01T08:00:00"
    }
  ],
  "total": 847,
  "page": 1,
  "per_page": 50,
  "query": "database backup",
  "response_time_ms": 23
}
```

**Errors:** `400` invalid regex, no search parameters.

---

### Export Results

```
GET /files/export
```

Export search results as CSV or JSON file download.

**Auth:** `auth_required` — **Rate limited**

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `format` | string | `csv` | Export format: `csv` or `json` |
| `q` | string | — | Search query |
| `regex` | string | — | Regex pattern |
| `ext` | string | — | Extension filter |
| `provider` | string | — | Provider filter |

```bash
curl -H "X-API-Key: cs_..." -o export.csv \
  "https://your-host/api/v1/files/export?q=backup&format=csv"
```

**Response:** File download with `Content-Disposition: attachment` header.

- **CSV columns:** filepath, filename, extension, size_bytes, url, bucket_name, provider_name, ai_classification, last_modified
- **Filename:** `cloudscan-export-<timestamp>.csv` or `.json`

---

### Random Files

```
GET /files/random
```

Get a random sample of indexed files.

**Auth:** `auth_required`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `count` | integer | `20` | Number of files (max `100`) |

```bash
curl -H "X-API-Key: cs_..." "https://your-host/api/v1/files/random?count=10"
```

**Response `200`:**

```json
{
  "items": [
    { "id": 567, "filepath": "...", "filename": "...", ... }
  ]
}
```

---

### File Preview

```
GET /files/:id/preview
```

Preview the first 4 KB of a file's content. Text files return escaped content; binary files return a summary.

**Auth:** `auth_required` — **Rate limited**

**Text-previewable extensions:** `env`, `txt`, `log`, `csv`, `json`, `xml`, `yaml`, `yml`, `md`, `ini`, `cfg`, `conf`, `sh`, `py`, `js`, `ts`, `css`, `html`, `sql`, `toml`, `key`, `pem`, `htaccess`, `gitignore`, `dockerfile`, `tf`, `tfvars`, `properties`, `htpasswd`

```bash
curl -H "X-API-Key: cs_..." "https://your-host/api/v1/files/1234/preview"
```

**Response `200` (text file):**

```json
{
  "file_id": 1234,
  "preview_type": "text",
  "content": "DB_HOST=prod-db.internal\nDB_USER=admin\nDB_PASS=...",
  "truncated": true,
  "size_bytes": 4096
}
```

**Response `200` (binary file):**

```json
{
  "file_id": 5678,
  "preview_type": "binary",
  "summary": "Binary file: PDF, 2.3 MB"
}
```

**Response `200` (error fetching):**

```json
{
  "file_id": 9999,
  "preview_type": "error",
  "error": "File not accessible"
}
```

**Errors:** `404` file not found.

---

## Saved Searches

### Save a Search

```
POST /searches/saved
```

**Auth:** `auth_required_strict`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Display name for the saved search |
| `query_params` | object | No | Query parameters (same keys as `GET /files`) |

```bash
curl -X POST -H "Authorization: Bearer ..." \
  -H "Content-Type: application/json" \
  -d '{"name": "Prod DB Backups", "query_params": {"q": "backup", "ext": "sql", "provider": "aws"}}' \
  https://your-host/api/v1/searches/saved
```

**Response `201`:**

```json
{
  "id": 1,
  "user_id": 1,
  "name": "Prod DB Backups",
  "query_params": {"q": "backup", "ext": "sql", "provider": "aws"},
  "created_at": "2025-03-10T14:30:00"
}
```

**Errors:** `400` missing name, `401` not authenticated.

---

### List Saved Searches

```
GET /searches/saved
```

**Auth:** `auth_required_strict`

**Response `200`:**

```json
{
  "items": [
    {
      "id": 1,
      "name": "Prod DB Backups",
      "query_params": {"q": "backup", "ext": "sql", "provider": "aws"},
      "created_at": "2025-03-10T14:30:00"
    }
  ]
}
```

---

### Delete Saved Search

```
DELETE /searches/saved/:id
```

**Auth:** `auth_required_strict`

```bash
curl -X DELETE -H "Authorization: Bearer ..." https://your-host/api/v1/searches/saved/1
```

**Response `200`:**

```json
{
  "message": "Deleted"
}
```

**Errors:** `404` not found or not owned by user.

---

## Buckets

### List Buckets

```
GET /buckets
```

**Auth:** `auth_required` — **Rate limited**

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | — | Filter by provider name |
| `status` | string | — | Filter: `open`, `closed`, `partial`, `error`, `unknown` |
| `search` | string | — | Substring search on bucket name |
| `page` | integer | `1` | Page number |
| `per_page` | integer | `50` | Results per page (max `200`) |

```bash
curl -H "X-API-Key: cs_..." "https://your-host/api/v1/buckets?provider=aws&status=open&page=1"
```

**Response `200`:**

```json
{
  "items": [
    {
      "id": 42,
      "name": "company-backups",
      "region": "us-east-1",
      "url": "https://company-backups.s3.amazonaws.com",
      "status": "open",
      "file_count": 1523,
      "total_size_bytes": 5368709120,
      "first_seen": "2025-02-15T08:00:00",
      "last_scanned": "2025-03-10T12:00:00",
      "risk_score": 85,
      "risk_level": "critical",
      "provider_name": "aws",
      "provider_display": "Amazon S3"
    }
  ],
  "total": 234,
  "page": 1,
  "per_page": 50
}
```

---

### Get Bucket Detail

```
GET /buckets/:id
```

Returns bucket metadata with paginated file listing.

**Auth:** `auth_required`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `page` | integer | `1` | File list page |
| `per_page` | integer | `100` | Files per page (max `500`) |

```bash
curl -H "X-API-Key: cs_..." "https://your-host/api/v1/buckets/42?page=1&per_page=50"
```

**Response `200`:**

```json
{
  "id": 42,
  "name": "company-backups",
  "region": "us-east-1",
  "url": "https://company-backups.s3.amazonaws.com",
  "status": "open",
  "file_count": 1523,
  "total_size_bytes": 5368709120,
  "risk_score": 85,
  "risk_level": "critical",
  "provider_name": "aws",
  "provider_display": "Amazon S3",
  "files": {
    "items": [ { "id": 1, "filepath": "...", ... } ],
    "total": 1523,
    "page": 1,
    "per_page": 50
  }
}
```

**Errors:** `404` bucket not found.

---

## Statistics & Analytics

### Summary Stats

```
GET /stats
```

**Auth:** None (public)

```bash
curl https://your-host/api/v1/stats
```

**Response `200`:**

```json
{
  "total_files": 125000,
  "total_buckets": 3400,
  "open_buckets": 890,
  "total_size_bytes": 1099511627776,
  "providers": [
    { "name": "aws", "display_name": "Amazon S3", "bucket_count": 2100, "file_count": 89000 }
  ],
  "top_extensions": [
    { "extension": "pdf", "count": 15000 }
  ],
  "recent_buckets": [
    { "id": 42, "name": "company-backups", "status": "open", "file_count": 1523, "provider_name": "aws" }
  ]
}
```

---

### Discovery Timeline

```
GET /stats/timeline
```

Time-series data showing files and buckets discovered per day.

**Auth:** `auth_required`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `days` | integer | `30` | Lookback period (max `365`) |

```bash
curl -H "X-API-Key: cs_..." "https://your-host/api/v1/stats/timeline?days=30"
```

**Response `200`:**

```json
{
  "files_timeline": [
    { "day": "2025-03-01", "count": 450 },
    { "day": "2025-03-02", "count": 320 }
  ],
  "buckets_timeline": [
    { "day": "2025-03-01", "count": 12 },
    { "day": "2025-03-02", "count": 8 }
  ],
  "days": 30
}
```

---

### Analytics Breakdown

```
GET /stats/breakdown
```

Categorical distributions for risk, provider, classification, status, and extensions.

**Auth:** `auth_required`

```bash
curl -H "X-API-Key: cs_..." "https://your-host/api/v1/stats/breakdown"
```

**Response `200`:**

```json
{
  "risk_distribution": [
    { "risk_level": "critical", "count": 45 },
    { "risk_level": "high", "count": 120 },
    { "risk_level": "medium", "count": 340 },
    { "risk_level": "low", "count": 890 }
  ],
  "provider_distribution": [
    { "name": "aws", "display_name": "Amazon S3", "bucket_count": 2100, "file_count": 89000 }
  ],
  "classification_distribution": [
    { "ai_classification": "credentials", "count": 230 }
  ],
  "status_distribution": [
    { "status": "open", "count": 890 },
    { "status": "closed", "count": 2100 }
  ],
  "extension_distribution": [
    { "extension": "pdf", "count": 15000 }
  ]
}
```

---

## Providers

### List Providers

```
GET /providers
```

**Auth:** None (public)

```bash
curl https://your-host/api/v1/providers
```

**Response `200`:**

```json
{
  "items": [
    {
      "id": 1,
      "name": "aws",
      "display_name": "Amazon S3",
      "bucket_term": "bucket",
      "endpoint_pattern": "https://{name}.s3.{region}.amazonaws.com",
      "created_at": "2025-01-01T00:00:00"
    }
  ]
}
```

---

## Scans

### Start a Scan

```
POST /scans
```

Launch a cloud storage discovery scan. Progress is streamed via [SSE](#real-time-events-sse).

**Auth:** `auth_required`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keywords` | string[] | Yes* | Search keywords (*required if no `companies`) |
| `companies` | string[] | Yes* | Company names (*required if no `keywords`) |
| `providers` | string[] | No | Providers to scan (defaults to all) |
| `max_names` | integer | No | Max bucket names to generate (default `1000`, max `10000`) |

```bash
curl -X POST -H "Authorization: Bearer ..." \
  -H "Content-Type: application/json" \
  -d '{"keywords": ["backup", "staging"], "providers": ["aws", "gcp"]}' \
  https://your-host/api/v1/scans
```

**Response `202`:**

```json
{
  "id": 7,
  "job_type": "discovery",
  "status": "pending",
  "config": {
    "keywords": ["backup", "staging"],
    "providers": ["aws", "gcp"],
    "max_names": 1000,
    "regions_per_provider": 5
  },
  "buckets_found": 0,
  "buckets_open": 0,
  "files_indexed": 0,
  "names_checked": 0,
  "started_at": null,
  "completed_at": null
}
```

**Errors:** `400` missing keywords and companies.

---

### List Scans

```
GET /scans
```

**Auth:** `auth_required`

**Response `200`:**

```json
{
  "items": [
    {
      "id": 7,
      "job_type": "discovery",
      "status": "completed",
      "buckets_found": 45,
      "buckets_open": 12,
      "files_indexed": 8934,
      "names_checked": 1000,
      "started_at": "2025-03-10T14:00:00",
      "completed_at": "2025-03-10T14:05:23",
      "created_at": "2025-03-10T13:59:58"
    }
  ]
}
```

---

### Get Scan Detail

```
GET /scans/:id
```

**Auth:** `auth_required`

**Response `200`:** Full scan job object (see [Scan Job](#scan-job) in Data Objects).

**Errors:** `404` scan not found.

---

### Cancel Scan

```
POST /scans/:id/cancel
```

**Auth:** `auth_required`

```bash
curl -X POST -H "Authorization: Bearer ..." https://your-host/api/v1/scans/7/cancel
```

**Response `200`:**

```json
{
  "message": "Scan cancelled"
}
```

**Errors:** `404` scan not found or already complete.

---

### Scan Debug Info

```
GET /scans/debug
```

Debug endpoint showing active scan threads and recent jobs.

**Auth:** None (public)

**Response `200`:**

```json
{
  "active_thread_ids": [7],
  "sse_subscribers": 2,
  "recent_jobs": [
    {
      "id": 7,
      "status": "running",
      "names_checked": 450,
      "buckets_found": 12,
      "files_indexed": 3400
    }
  ]
}
```

---

## Real-time Events (SSE)

```
GET /events/scans
```

Server-Sent Events stream for real-time scan progress. No authentication required.

```bash
curl -N "https://your-host/api/v1/events/scans"
```

### Event Types

| Event | Description | Data Fields |
|-------|-------------|-------------|
| `connected` | Connection established | — |
| `scan_started` | Scan job began | `job_id`, `config` |
| `progress` | Periodic progress update | `job_id`, `names_checked`, `buckets_found`, `files_indexed`, `phase` |
| `bucket_found` | New bucket discovered | `job_id`, `bucket` (bucket object) |
| `scan_complete` | Scan finished | `job_id`, `stats` (final counters) |
| `scan_cancelled` | Scan was cancelled | `job_id` |
| `error` | Scan error | `job_id`, `error` |
| `monitor_progress` | Watchlist scan progress | `watchlist_id`, `checked`, `total` |
| `monitor_complete` | Watchlist scan finished | `watchlist_id`, `new_alerts` |

**Keepalive:** `: keepalive\n\n` every 15 seconds.

**Example event stream:**

```
event: connected
data: {}

event: scan_started
data: {"job_id": 7, "config": {"keywords": ["backup"], "providers": ["aws"]}}

event: progress
data: {"job_id": 7, "names_checked": 150, "buckets_found": 3, "files_indexed": 45, "phase": "scanning"}

event: bucket_found
data: {"job_id": 7, "bucket": {"id": 42, "name": "company-backups", "provider": "aws", "status": "open"}}

event: scan_complete
data: {"job_id": 7, "stats": {"buckets_found": 12, "buckets_open": 5, "files_indexed": 8934}}
```

---

## Monitoring — Watchlists

### Create Watchlist

```
POST /monitor/watchlists
```

**Auth:** `auth_required_strict`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Watchlist name |
| `keywords` | string[] | Yes | Keywords to monitor (min 1) |
| `companies` | string[] | No | Company names |
| `providers` | string[] | No | Providers to scan (defaults to all) |
| `scan_interval_hours` | integer | No | Hours between scans (default `24`) |

```bash
curl -X POST -H "Authorization: Bearer ..." \
  -H "Content-Type: application/json" \
  -d '{"name": "Prod Monitoring", "keywords": ["acme-corp", "acme-prod"], "scan_interval_hours": 6}' \
  https://your-host/api/v1/monitor/watchlists
```

**Response `201`:**

```json
{
  "id": 1,
  "user_id": 1,
  "name": "Prod Monitoring",
  "keywords": "[\"acme-corp\", \"acme-prod\"]",
  "companies": "[]",
  "providers": "[]",
  "is_active": true,
  "scan_interval_hours": 6,
  "last_scan_at": null,
  "next_scan_at": "2025-03-10T20:00:00",
  "created_at": "2025-03-10T14:00:00"
}
```

**Errors:** `400` missing name or keywords.

---

### List Watchlists

```
GET /monitor/watchlists
```

**Auth:** `auth_required_strict`

**Response `200`:**

```json
{
  "items": [ { watchlist objects } ]
}
```

---

### Get Watchlist Detail

```
GET /monitor/watchlists/:id
```

Returns watchlist with monitored assets.

**Auth:** `auth_required_strict`

**Response `200`:**

```json
{
  "id": 1,
  "name": "Prod Monitoring",
  "is_active": true,
  "assets": [
    {
      "id": 1,
      "bucket_id": 42,
      "bucket_name": "company-backups",
      "bucket_url": "https://company-backups.s3.amazonaws.com",
      "current_status": "open",
      "previous_status": null,
      "file_count_curr": 1523,
      "file_count_prev": 0,
      "first_detected": "2025-03-10T14:05:00",
      "provider_name": "aws",
      "provider_display": "Amazon S3"
    }
  ]
}
```

**Errors:** `404` not found or not owned by user.

---

### Update Watchlist

```
PUT /monitor/watchlists/:id
```

**Auth:** `auth_required_strict`

**Request Body:** Any combination of `name`, `keywords`, `companies`, `providers`, `scan_interval_hours`, `is_active`.

**Response `200`:** Updated watchlist object.

**Errors:** `404` not found.

---

### Delete Watchlist

```
DELETE /monitor/watchlists/:id
```

**Auth:** `auth_required_strict`

**Response `200`:** `{"message": "Deleted"}`

**Errors:** `404` not found.

---

### Trigger Watchlist Scan

```
POST /monitor/watchlists/:id/scan
```

Manually trigger a scan for this watchlist.

**Auth:** `auth_required_strict`

**Response `202`:**

```json
{
  "message": "Scan started",
  "watchlist_id": 1
}
```

**Errors:** `404` not found.

---

## Monitoring — Alerts

### List Alerts

```
GET /monitor/alerts
```

**Auth:** `auth_required_strict`

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `unread` | string | — | Set to `true` to filter unread only |
| `severity` | string | — | Filter: `critical`, `high`, `medium`, `low`, `info` |
| `page` | integer | `1` | Page number |
| `per_page` | integer | `50` | Results per page (max `200`) |

```bash
curl -H "Authorization: Bearer ..." \
  "https://your-host/api/v1/monitor/alerts?unread=true&severity=critical"
```

**Response `200`:**

```json
{
  "items": [
    {
      "id": 1,
      "watchlist_id": 1,
      "watchlist_name": "Prod Monitoring",
      "alert_type": "new_bucket",
      "severity": "critical",
      "title": "New open bucket: company-backups",
      "description": "Open AWS bucket with 1523 files",
      "bucket_id": 42,
      "bucket_name": "company-backups",
      "bucket_url": "https://company-backups.s3.amazonaws.com",
      "is_read": false,
      "is_resolved": false,
      "created_at": "2025-03-10T14:05:00"
    }
  ],
  "total": 15,
  "page": 1
}
```

### Alert Types

| Type | Severity | Description |
|------|----------|-------------|
| `new_bucket` | `high` | New bucket discovered by watchlist |
| `status_change` | `critical` (→open) / `info` (→closed) | Bucket status changed |
| `new_files` | `medium` | New files detected in monitored bucket |
| `sensitive_file` | `critical` | Sensitive file detected (credentials, keys, etc.) |

---

### Mark Alert Read

```
POST /monitor/alerts/:id/read
```

**Auth:** `auth_required_strict`

**Response `200`:** `{"message": "Marked read"}`

---

### Mark All Alerts Read

```
POST /monitor/alerts/read-all
```

**Auth:** `auth_required_strict`

**Response `200`:** `{"message": "All marked read"}`

---

### Resolve Alert

```
POST /monitor/alerts/:id/resolve
```

**Auth:** `auth_required_strict`

**Response `200`:** `{"message": "Resolved"}`

---

### Monitor Dashboard

```
GET /monitor/dashboard
```

Summary counts for the monitoring system.

**Auth:** `auth_required_strict`

**Response `200`:**

```json
{
  "watchlists": 3,
  "monitored_buckets": 42,
  "unread_alerts": 7,
  "alerts_by_severity": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "info": 3
  }
}
```

---

## Webhooks

### Create Webhook

```
POST /monitor/webhooks
```

**Auth:** `auth_required_strict`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Webhook name |
| `url` | string | Yes | Webhook URL (must start with `http://` or `https://`) |
| `secret` | string | No | HMAC-SHA256 signing secret |
| `event_types` | string[] | No | Severity levels to receive (default: `["critical", "high"]`) |

```bash
curl -X POST -H "Authorization: Bearer ..." \
  -H "Content-Type: application/json" \
  -d '{"name": "Slack Alerts", "url": "https://hooks.slack.com/...", "secret": "my-secret", "event_types": ["critical"]}' \
  https://your-host/api/v1/monitor/webhooks
```

**Response `201`:**

```json
{
  "id": 1,
  "name": "Slack Alerts",
  "url": "https://hooks.slack.com/...",
  "secret": "my-secret",
  "event_types": "[\"critical\"]",
  "is_active": true,
  "failure_count": 0,
  "created_at": "2025-03-10T14:00:00"
}
```

**Errors:** `400` missing name/url, invalid URL.

---

### List Webhooks

```
GET /monitor/webhooks
```

**Auth:** `auth_required_strict`

**Response `200`:** `{"items": [ webhook objects ]}`

---

### Update Webhook

```
PUT /monitor/webhooks/:id
```

**Auth:** `auth_required_strict`

**Request Body:** Any combination of `name`, `url`, `secret`, `event_types`, `is_active`.

**Response `200`:** Updated webhook object.

---

### Delete Webhook

```
DELETE /monitor/webhooks/:id
```

**Auth:** `auth_required_strict`

**Response `200`:** `{"message": "Deleted"}`

---

### Test Webhook

```
POST /monitor/webhooks/:id/test
```

Sends a test payload to the webhook URL.

**Auth:** `auth_required_strict`

**Response `200`:**

```json
{
  "success": true,
  "status": 200
}
```

---

### Webhook Payload Format

When an alert matches a webhook's `event_types`, CloudScan sends a POST request:

**Headers:**

| Header | Value |
|--------|-------|
| `Content-Type` | `application/json` |
| `X-CloudScan-Event` | `alert` or `test` |
| `X-CloudScan-Signature` | HMAC-SHA256 hex digest (only if `secret` is set) |

**Body:**

```json
{
  "event": "alert",
  "timestamp": "2025-03-10T14:05:00Z",
  "alert": {
    "id": 1,
    "alert_type": "sensitive_file",
    "severity": "critical",
    "title": "Sensitive file detected: .env",
    "description": "Found credentials file in open bucket",
    "bucket_name": "company-backups",
    "bucket_url": "https://company-backups.s3.amazonaws.com"
  }
}
```

**Signature Verification (Python):**

```python
import hmac, hashlib

signature = request.headers["X-CloudScan-Signature"]
expected = hmac.new(secret.encode(), request.data, hashlib.sha256).hexdigest()
assert hmac.compare_digest(signature, expected)
```

**Failure Handling:** Webhooks are automatically disabled after 10 consecutive delivery failures (non-2xx responses or timeouts).

---

## AI Features

AI features require an AI provider to be configured (Anthropic, OpenAI, or Ollama).

### AI Status

```
GET /ai/status
```

**Auth:** None (public)

```bash
curl https://your-host/api/v1/ai/status
```

**Response `200`:**

```json
{
  "available": true,
  "active_provider": "anthropic",
  "provider_display_name": "Anthropic Claude",
  "model_fast": "claude-haiku",
  "model_quality": "claude-sonnet",
  "providers": [
    {
      "name": "anthropic",
      "display_name": "Anthropic Claude",
      "models": { "fast": "claude-haiku", "quality": "claude-sonnet" }
    }
  ],
  "features": ["classify", "risk_score", "nl_search", "report", "suggest_keywords", "prioritize_alerts"]
}
```

---

### Switch AI Provider

```
POST /ai/provider
```

**Auth:** `auth_required`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider` | string | Yes | `anthropic`, `openai`, or `ollama` |

**Response `200`:**

```json
{
  "message": "Switched to Anthropic Claude",
  "active_provider": "anthropic",
  "model_fast": "claude-haiku",
  "model_quality": "claude-sonnet"
}
```

---

### Classify Bucket Files

```
POST /ai/classify/:bucket_id
```

Uses AI to classify files in a bucket by content type.

**Auth:** `auth_required`

**Response `200`:**

```json
{
  "classified": 25,
  "results": [
    { "filepath": "config/database.yml", "classification": "credentials", "confidence": 0.95 }
  ]
}
```

---

### Get Classifications

```
GET /ai/classifications
```

**Auth:** `auth_required`

| Param | Type | Description |
|-------|------|-------------|
| `bucket_id` | integer | Filter by bucket (optional) |

**Response `200`:**

```json
{
  "summary": {
    "credentials": 45,
    "database": 120,
    "source_code": 890,
    "documents": 2300
  }
}
```

---

### Calculate Risk Score

```
POST /ai/risk/:bucket_id
```

AI-powered risk assessment for a bucket.

**Auth:** `auth_required`

**Response `200`:**

```json
{
  "risk_score": 85,
  "risk_level": "critical"
}
```

---

### Natural Language Search

```
POST /ai/search
```

Converts natural language queries to structured search parameters.

**Auth:** `auth_required` — **Rate limited**

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | Yes | Natural language query |
| `page` | integer | No | Page number (default `1`) |
| `per_page` | integer | No | Results per page (default `50`, max `200`) |

```bash
curl -X POST -H "Authorization: Bearer ..." \
  -H "Content-Type: application/json" \
  -d '{"query": "find large SQL files in AWS buckets"}' \
  https://your-host/api/v1/ai/search
```

**Response `200`:**

```json
{
  "items": [ { file objects } ],
  "total": 42,
  "parsed_params": {
    "q": "sql",
    "ext": "sql",
    "provider": "aws",
    "sort": "size_desc"
  },
  "original_query": "find large SQL files in AWS buckets",
  "response_time_ms": 1200
}
```

---

### Generate Security Report

```
POST /ai/report
```

Generate a comprehensive AI security report.

**Auth:** `auth_required_strict`

**Response `200`:**

```json
{
  "title": "CloudScan Security Assessment",
  "summary": "Analysis of 3400 buckets across 5 providers...",
  "key_findings": ["45 critical-risk buckets with exposed credentials", "..."],
  "risk_distribution": { "critical": 45, "high": 120, "medium": 340, "low": 890 },
  "recommendations": ["Immediately secure buckets with exposed .env files", "..."],
  "generated_at": "2025-03-10T14:30:00"
}
```

---

### Suggest Keywords

```
POST /ai/suggest-keywords
```

AI-powered keyword suggestions for company scanning.

**Auth:** `auth_required`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `company` | string | Yes | Company name |

**Response `200`:**

```json
{
  "company": "Acme Corp",
  "suggestions": ["acme-corp", "acme-prod", "acme-staging", "acmecorp-backup", "acme-data"]
}
```

---

### Prioritize Alerts

```
POST /ai/prioritize-alerts
```

Use AI to score and prioritize unread alerts.

**Auth:** `auth_required_strict`

**Response `200`:**

```json
{
  "prioritized": 15,
  "alerts": [
    {
      "id": 1,
      "ai_priority_score": 95,
      "severity": "critical",
      "title": "Sensitive file detected: .env"
    }
  ]
}
```

---

## Data Objects

### File

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Unique file ID |
| `filepath` | string | Full file path within the bucket |
| `filename` | string | File name only |
| `extension` | string | File extension (without dot) |
| `size_bytes` | integer | File size in bytes |
| `url` | string | Direct URL to the file |
| `bucket_name` | string | Parent bucket name |
| `bucket_url` | string | Parent bucket URL |
| `region` | string | Cloud region |
| `provider_name` | string | Provider identifier |
| `provider_display` | string | Provider display name |
| `ai_classification` | string | AI-assigned classification (if available) |
| `last_modified` | string | ISO 8601 timestamp |

### Bucket

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Unique bucket ID |
| `name` | string | Bucket name |
| `region` | string | Cloud region |
| `url` | string | Bucket URL |
| `status` | string | `open`, `closed`, `partial`, `error`, `unknown` |
| `file_count` | integer | Number of indexed files |
| `total_size_bytes` | integer | Total size of all files |
| `first_seen` | string | When bucket was first discovered |
| `last_scanned` | string | Last scan timestamp |
| `risk_score` | integer | Risk score (0-100) |
| `risk_level` | string | `critical`, `high`, `medium`, `low` |
| `provider_name` | string | Provider identifier |
| `provider_display` | string | Provider display name |

### Alert

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Unique alert ID |
| `watchlist_id` | integer | Parent watchlist ID |
| `watchlist_name` | string | Parent watchlist name |
| `alert_type` | string | `new_bucket`, `new_files`, `status_change`, `sensitive_file` |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `title` | string | Alert title |
| `description` | string | Alert description |
| `bucket_id` | integer | Related bucket ID |
| `bucket_name` | string | Related bucket name |
| `is_read` | boolean | Read status |
| `is_resolved` | boolean | Resolution status |
| `ai_priority_score` | integer | AI-assigned priority (0-100) |
| `created_at` | string | ISO 8601 timestamp |

### Scan Job

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Unique job ID |
| `job_type` | string | `discovery`, `enumerate`, `rescan` |
| `status` | string | `pending`, `running`, `completed`, `failed`, `cancelled` |
| `config` | object | Scan configuration |
| `buckets_found` | integer | Total buckets found |
| `buckets_open` | integer | Open buckets found |
| `files_indexed` | integer | Files indexed |
| `names_checked` | integer | Bucket names checked |
| `started_at` | string | Start timestamp |
| `completed_at` | string | Completion timestamp |
| `errors` | string | JSON array of errors (if any) |
