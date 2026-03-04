# CloudScan Scanner Engine — Architecture

## Overview

The scanner engine discovers publicly accessible cloud storage buckets by:

1. **Generating** candidate bucket names using multiple strategies
2. **Probing** each name against cloud provider endpoints via async HTTP
3. **Parsing** XML file listings from accessible buckets
4. **Persisting** results to the database in real-time
5. **Streaming** events to connected clients via SSE

## Name Generation Strategies

### 1. Common Word Combinations
Combines common prefixes (`backup`, `data`, `dev`, `staging`) with suffixes (`prod`, `bucket`, `storage`, `2025`) using separators (`-`, `.`, `_`, `""`).

Generates ~5,000 names from 35 prefixes × 25 suffixes × 4 separators.

### 2. Keyword Permutations
User-supplied keywords are combined with common words:
- `keyword` → `keyword-backup`, `backup-keyword`, `keyword.prod`, etc.

### 3. Company Name Patterns
Company names get expanded into common enterprise patterns:
- `acme-corp` → `acme-corp-dev`, `acme-corp-staging`, `acme-corp-prod`
- `acme-corp` → `acme-corp-api-prod`, `acme-corp-web-dev`, etc.

### 4. Random Alphanumeric
A small percentage of random strings (6-14 chars) to catch arbitrary bucket names.

### Validation
All generated names are validated against S3 bucket naming rules:
- 3-63 characters
- Lowercase alphanumeric, hyphens, dots only
- No `xn--` prefix (internationalized domain names)
- No consecutive dots

## Multi-Provider Support

| Provider | Endpoint Template | Regions |
|----------|-------------------|---------|
| AWS S3 | `https://{name}.s3.{region}.amazonaws.com` | 13 |
| Azure Blob | `https://{name}.blob.core.windows.net` | — |
| GCP Storage | `https://storage.googleapis.com/{name}` | — |
| DigitalOcean | `https://{name}.{region}.digitaloceanspaces.com` | 6 |
| Alibaba OSS | `https://{name}.oss-{region}.aliyuncs.com` | 7 |

## Status Detection

| HTTP Response | Status | Meaning |
|---------------|--------|---------|
| 200 + XML listing | `open` | Bucket is publicly listable |
| 403 / AccessDenied | `closed` | Bucket exists but requires auth |
| 404 / NoSuchBucket | `not_found` | Bucket does not exist |
| 200 without listing | `partial` | Bucket accessible but not listable |
| Timeout / error | `error` | Network or server error |

## Concurrency Model

```
┌─────────────────────────────────────────────┐
│           asyncio Event Loop                 │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │     asyncio.Semaphore(50)             │   │
│  │                                        │   │
│  │  Task 1 ─→ HTTP GET → parse → emit    │   │
│  │  Task 2 ─→ HTTP GET → parse → emit    │   │
│  │  ...                                   │   │
│  │  Task 50 ─→ HTTP GET → parse → emit   │   │
│  └──────────────────────────────────────┘   │
│                                              │
│  asyncio.as_completed() yields results      │
│  as each task finishes                       │
└─────────────────────────────────────────────┘
```

- Default concurrency: 50 simultaneous HTTP requests
- TCP connection pooling with DNS caching (300s TTL)
- Configurable timeout per request (default: 10s)
- `as_completed()` enables real-time result streaming

## XML Parsing

Open buckets return S3-compatible XML:

```xml
<ListBucketResult>
  <Contents>
    <Key>backups/database.sql</Key>
    <Size>52428800</Size>
    <LastModified>2025-01-15T08:30:00.000Z</LastModified>
    <ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag>
  </Contents>
  <IsTruncated>true</IsTruncated>
  <NextMarker>backups/next-file.sql</NextMarker>
</ListBucketResult>
```

The parser:
- Strips XML namespaces for cross-provider compatibility
- Extracts `Key`, `Size`, `LastModified`, `ETag`
- Filters out uninteresting files (images, fonts, video, OS files)
- Handles pagination via `IsTruncated` + `NextMarker`

## Deep Enumeration

For known-open buckets, `enumerate_bucket_deep()` performs paginated crawling:

1. Request with `max-keys=1000`
2. Parse file listing
3. Check `IsTruncated` — if true, use `NextMarker` for next page
4. Repeat until all files indexed or `max_keys` reached
5. Default cap: 100,000 files per bucket

## Data Flow

```
Name Generator
    ↓
BucketScanner.check_bucket() ← async HTTP probe
    ↓
on_result callback
    ↓
ScanService.on_result()
    ├── BucketStore.upsert() → DB
    ├── FileStore.insert_batch() → DB + FTS5
    └── broadcast_event() → SSE → Frontend
```

## File Filtering

Skipped extensions (noise reduction):
- Images: png, jpg, jpeg, gif, bmp, tiff, webp, svg, ico
- Fonts: woff, woff2, ttf, eot, otf
- Media: mp3, mp4, avi, mov, wmv, flv, mkv, webm
- OS: DS_Store, thumbs.db

## Performance Characteristics

| Metric | Typical | Maximum |
|--------|---------|---------|
| Names/second (scanning) | ~500 | ~2,000 |
| Open buckets/1000 names | 0-5 | Varies |
| Files parsed/second | ~10,000 | ~50,000 |
| Memory usage | ~50MB | ~200MB |
| DB insert rate | ~5,000 files/s | ~20,000 files/s |
