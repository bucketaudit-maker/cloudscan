# CloudScan API Documentation

Base URL: `http://localhost:8000/api/v1`

## Authentication

CloudScan supports three authentication methods:

### Bearer Token (JWT)
```
Authorization: Bearer eyJhbG...
```
Obtained from `/auth/login` or `/auth/register`. Expires after 24 hours.

### API Key (Header)
```
X-API-Key: cs_your_api_key_here
```
Generated on registration. Does not expire.

### API Key (Query Parameter)
```
GET /api/v1/files?q=backup&access_token=cs_your_api_key_here
```

## Rate Limits

| Tier | Requests/Day | Price |
|------|-------------|-------|
| Free | 100 | $0 |
| Premium | 5,000 | Contact |
| Enterprise | 50,000 | Contact |

Rate limit resets daily at midnight UTC. When exceeded, responses return `429 Too Many Requests` with a `reset_at` timestamp.

---

## Endpoints

### Health

#### `GET /health`
```json
{ "status": "ok", "timestamp": "2025-03-04T12:00:00", "version": "1.0.0" }
```

---

### Authentication

#### `POST /auth/register`
Create an account. Returns JWT token and API key.

**Body:**
```json
{
  "email": "user@example.com",
  "username": "myuser",
  "password": "minimum8chars"
}
```

**Response (201):**
```json
{
  "token": "eyJhbG...",
  "api_key": "cs_a1b2c3...",
  "user": { "id": 1, "email": "user@example.com", "username": "myuser", "tier": "free" }
}
```

#### `POST /auth/login`
**Body:**
```json
{ "email": "user@example.com", "password": "minimum8chars" }
```

**Response (200):**
```json
{
  "token": "eyJhbG...",
  "user": { "id": 1, "email": "user@example.com", "username": "myuser", "tier": "free", "api_key": "cs_..." }
}
```

#### `GET /auth/me` (requires auth)
Returns current authenticated user profile.

---

### File Search

#### `GET /files`
Full-text search across all indexed files.

**Parameters:**

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `q` | string | * | Search query (FTS5 syntax, supports NOT) |
| `ext` | string | | Comma-separated extensions: `sql,csv,json` |
| `exclude_ext` | string | | Extensions to exclude: `log,txt` |
| `provider` | string | | Filter by provider: `aws`, `azure`, `gcp`, `digitalocean`, `alibaba` |
| `bucket` | string | | Filter by bucket name (partial match) |
| `min_size` | integer | | Minimum file size in bytes |
| `max_size` | integer | | Maximum file size in bytes |
| `sort` | string | | Sort order: `relevance`, `size_asc`, `size_desc`, `newest`, `oldest`, `filename` |
| `page` | integer | | Page number (default: 1) |
| `per_page` | integer | | Results per page (default: 50, max: 200) |

*At least one of `q`, `ext`, or `provider` is required.

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "bucket_id": 5,
      "filepath": "backups/database.sql",
      "filename": "database.sql",
      "extension": "sql",
      "size_bytes": 52428800,
      "last_modified": "2025-01-15T08:30:00",
      "url": "https://bucket.s3.amazonaws.com/backups/database.sql",
      "bucket_name": "company-backup-prod",
      "bucket_url": "https://company-backup-prod.s3.amazonaws.com",
      "region": "us-east-1",
      "provider_name": "aws",
      "provider_display": "Amazon Web Services"
    }
  ],
  "total": 185,
  "page": 1,
  "per_page": 50,
  "query": "database",
  "response_time_ms": 6
}
```

**Examples:**
```bash
# Search for SQL backups
GET /files?q=backup.sql&ext=sql,gz

# Find credentials in AWS
GET /files?q=credentials&provider=aws

# Large files only
GET /files?q=database&min_size=10000000&sort=size_desc

# Exclude log files
GET /files?q=config&exclude_ext=log,txt
```

#### `GET /files/random`
Returns random files from the index. Useful for discovery.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `count` | integer | 20 | Number of files (max: 100) |

---

### Buckets

#### `GET /buckets`
List discovered buckets with optional filtering.

| Param | Type | Description |
|-------|------|-------------|
| `provider` | string | Filter by provider name |
| `status` | string | Filter: `open`, `closed`, `partial` |
| `search` | string | Search bucket names |
| `page` | integer | Page number |
| `per_page` | integer | Results per page (max: 200) |

#### `GET /buckets/:id`
Bucket details with paginated file listing.

| Param | Type | Description |
|-------|------|-------------|
| `page` | integer | File listing page |
| `per_page` | integer | Files per page (max: 500) |

---

### Statistics

#### `GET /stats`
Database-wide statistics. No authentication required.

**Response:**
```json
{
  "total_files": 2540,
  "total_buckets": 28,
  "open_buckets": 24,
  "total_size_bytes": 63294817280,
  "providers": [
    { "name": "aws", "display_name": "Amazon Web Services", "bucket_count": 12, "file_count": 1523 }
  ],
  "top_extensions": [
    { "extension": "json", "count": 482 }
  ],
  "recent_buckets": [...]
}
```

---

### Scans

#### `POST /scans` (requires auth)
Start a discovery scan. Results stream via SSE.

**Body:**
```json
{
  "keywords": ["backup", "credentials", "secret"],
  "companies": ["acme-corp"],
  "providers": ["aws", "gcp"],
  "max_names": 1000
}
```

**Response (202):**
```json
{
  "id": 1,
  "job_type": "discovery",
  "status": "pending",
  "config": "{...}",
  "created_at": "2025-03-04T12:00:00"
}
```

#### `GET /scans/:id` (requires auth)
Get scan job status and progress.

#### `GET /scans` (requires auth)
List recent scan jobs (last 50).

#### `POST /scans/:id/cancel` (requires auth)
Cancel a running scan.

---

### Real-Time Events (SSE)

#### `GET /events/scans`
Server-Sent Events stream for real-time scan updates.

**Event Types:**

| Event | Description |
|-------|-------------|
| `connected` | Initial connection confirmation |
| `scan_started` | Scan job has begun |
| `progress` | Scan progress update (every 50 checks) |
| `bucket_found` | A bucket was discovered |
| `scan_complete` | Scan finished |
| `error` | Scan error occurred |

**Example (JavaScript):**
```javascript
const es = new EventSource('/api/v1/events/scans');

es.addEventListener('progress', (e) => {
  const data = JSON.parse(e.data);
  console.log(`${data.names_checked}/${data.names_total} checked, ${data.buckets_open} open`);
});

es.addEventListener('bucket_found', (e) => {
  const { bucket } = JSON.parse(e.data);
  console.log(`Found: ${bucket.provider}://${bucket.name} [${bucket.status}]`);
});

es.addEventListener('scan_complete', (e) => {
  console.log('Scan done:', JSON.parse(e.data).stats);
  es.close();
});
```

**Progress payload:**
```json
{
  "job_id": 1,
  "phase": "scanning",
  "provider": "aws",
  "names_total": 3000,
  "names_checked": 1500,
  "buckets_found": 12,
  "buckets_open": 4,
  "files_indexed": 847,
  "current_bucket": "company-backup-prod",
  "errors": 3,
  "elapsed_ms": 15000
}
```

---

### Providers

#### `GET /providers`
List supported cloud providers.

**Response:**
```json
{
  "items": [
    { "id": 1, "name": "aws", "display_name": "Amazon Web Services", "bucket_term": "bucket" },
    { "id": 2, "name": "azure", "display_name": "Microsoft Azure", "bucket_term": "container" },
    { "id": 3, "name": "gcp", "display_name": "Google Cloud Platform", "bucket_term": "bucket" },
    { "id": 4, "name": "digitalocean", "display_name": "DigitalOcean", "bucket_term": "space" },
    { "id": 5, "name": "alibaba", "display_name": "Alibaba Cloud", "bucket_term": "bucket" }
  ]
}
```

---

## Error Responses

All errors follow this format:
```json
{ "error": "Human-readable error message" }
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request (missing/invalid params) |
| 401 | Authentication required or invalid |
| 403 | Account disabled |
| 404 | Resource not found |
| 409 | Conflict (duplicate email/username) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
