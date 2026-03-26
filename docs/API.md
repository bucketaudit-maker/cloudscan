# CloudScan API — Quick Reference

> **Full API documentation** with request/response examples: [`../API.md`](../API.md)

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

### CSRF Tokens

All state-changing requests (POST, PUT, DELETE) require a CSRF token:

```bash
# 1. Fetch a single-use CSRF token
curl http://localhost:8000/api/v1/csrf-token

# 2. Include it in your request
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer ..." \
  -H "X-CSRF-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"keywords": ["backup"]}'
```

## Rate Limits

| Tier | Requests/Day | Scans/Day | Schedules | Keywords | Concurrent Scans | Webhooks | AI |
|------|-------------|-----------|-----------|----------|------------------|----------|----|
| Free | 100 | 3 | 1 | 10 | 1 | 0 | No |
| Premium | 5,000 | 50 | 10 | 100 | 3 | 5 | Yes |
| Enterprise | 50,000 | Unlimited | Unlimited | Unlimited | 10 | Unlimited | Yes |

Rate limit resets daily at midnight UTC. When exceeded, responses return `429 Too Many Requests` with a `reset_at` timestamp.

---

## Endpoint Summary (80+)

### Public Endpoints (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/stats` | Aggregate statistics |
| `GET` | `/providers` | Cloud provider list |
| `GET` | `/events/scans` | SSE real-time stream |
| `GET` | `/ai/status` | AI provider status |
| `GET` | `/csrf-token` | Get CSRF token |
| `GET` | `/pricing` | View pricing tiers |

### Authentication & Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Create account |
| `POST` | `/auth/login` | Login (supports 2FA) |
| `GET` | `/auth/me` | Current user profile |
| `POST` | `/auth/forgot-password` | Request password reset |
| `POST` | `/auth/reset-password` | Reset password with token |
| `POST` | `/auth/rotate-key` | Regenerate API key |
| `PUT` | `/auth/settings` | Update username/password |
| `POST` | `/auth/upgrade` | Upgrade tier |
| `GET` | `/auth/tier-limits` | View tier limits |

### Two-Factor Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/2fa/setup` | Initialize TOTP setup |
| `POST` | `/auth/2fa/confirm` | Confirm 2FA enrollment |
| `POST` | `/auth/2fa/verify` | Verify 2FA code on login |
| `POST` | `/auth/2fa/disable` | Disable 2FA |
| `GET` | `/auth/2fa/status` | Check 2FA status |

### File Search & Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/files` | Full-text / regex file search |
| `GET` | `/files/export` | Export results (CSV, JSON, PDF, SARIF) |
| `GET` | `/files/random` | Random interesting files |
| `GET` | `/files/:id/preview` | Preview file content (first 4KB) |

### Saved Searches

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/searches/saved` | Save a search query |
| `GET` | `/searches/saved` | List saved searches |
| `DELETE` | `/searches/saved/:id` | Delete saved search |

### Buckets & Tags

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/buckets` | List discovered buckets |
| `GET` | `/buckets/:id` | Bucket detail + file listing |
| `GET` | `/buckets/:id/tags` | Get bucket tags |
| `POST` | `/buckets/:id/tags` | Add/manage bucket tags |

### Bookmarks

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/bookmarks` | Bookmark a file/bucket |
| `GET` | `/bookmarks` | List bookmarks |
| `GET` | `/bookmarks/check` | Check if item is bookmarked |
| `GET` | `/bookmarks/ids` | Get all bookmark IDs |

### Statistics & Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/stats` | Summary statistics |
| `GET` | `/stats/timeline` | Discovery timeline (daily) |
| `GET` | `/stats/breakdown` | Risk/provider/classification breakdown |
| `GET` | `/dashboard/executive` | Executive dashboard |
| `GET` | `/dashboard/risk-trends` | Risk trend analysis |
| `GET` | `/dashboard/remediation-sla` | Remediation SLA metrics |

### Scans & Scheduling

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scans` | Start discovery scan |
| `GET` | `/scans` | List scan history |
| `GET` | `/scans/:id` | Scan job detail |
| `POST` | `/scans/:id/cancel` | Cancel running scan |
| `GET` | `/scans/debug` | Debug scan status |
| `POST` | `/scans/schedules` | Create recurring schedule |
| `GET` | `/scans/schedules` | List schedules |
| `GET` | `/scans/schedules/:id` | Schedule detail |
| `PUT` | `/scans/schedules/:id` | Update schedule |
| `DELETE` | `/scans/schedules/:id` | Delete schedule |
| `POST` | `/scans/schedules/:id/toggle` | Enable/disable schedule |
| `POST` | `/scans/schedules/:id/run` | Manually trigger schedule |

### Monitoring — Watchlists

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/monitor/watchlists` | Create watchlist |
| `GET` | `/monitor/watchlists` | List watchlists |
| `GET` | `/monitor/watchlists/:id` | Watchlist detail + assets |
| `PUT` | `/monitor/watchlists/:id` | Update watchlist |
| `DELETE` | `/monitor/watchlists/:id` | Delete watchlist |
| `POST` | `/monitor/watchlists/:id/scan` | Trigger watchlist scan |

### Monitoring — Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/monitor/alerts` | List alerts (filter by severity/unread) |
| `POST` | `/monitor/alerts/:id/read` | Mark alert as read |
| `POST` | `/monitor/alerts/read-all` | Mark all alerts as read |
| `POST` | `/monitor/alerts/:id/resolve` | Resolve alert |
| `POST` | `/monitor/alerts/bulk-resolve` | Bulk resolve alerts |
| `POST` | `/monitor/alerts/bulk-read` | Bulk mark as read |
| `GET` | `/monitor/dashboard` | Monitoring summary |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/monitor/webhooks` | Create webhook |
| `GET` | `/monitor/webhooks` | List webhooks |
| `PUT` | `/monitor/webhooks/:id` | Update webhook |
| `DELETE` | `/monitor/webhooks/:id` | Delete webhook |
| `POST` | `/monitor/webhooks/:id/test` | Test webhook delivery |

### Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/notifications` | Get notifications |
| `GET` | `/notifications/unread-count` | Unread count |
| `POST` | `/notifications/:id/read` | Mark as read |
| `POST` | `/notifications/read-all` | Mark all as read |
| `GET` | `/notifications/prefs` | Get notification preferences |
| `PUT` | `/notifications/prefs` | Update preferences |
| `POST` | `/notifications/slack` | Configure Slack |
| `DELETE` | `/notifications/slack` | Remove Slack config |
| `POST` | `/notifications/slack/test` | Test Slack integration |

### AI Features

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/ai/status` | AI provider status and capabilities |
| `POST` | `/ai/provider` | Switch AI provider |
| `POST` | `/ai/classify/:bucket_id` | Classify bucket files by sensitivity |
| `GET` | `/ai/classifications` | Get all AI classifications |
| `POST` | `/ai/risk/:bucket_id` | Compute bucket risk score |
| `POST` | `/ai/search` | Natural language search |
| `POST` | `/ai/report` | Generate AI security report |
| `POST` | `/ai/suggest-keywords` | AI keyword suggestions |
| `POST` | `/ai/prioritize-alerts` | AI alert prioritization |

### Organizations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/orgs` | Create organization |
| `GET` | `/orgs` | List organizations |
| `GET` | `/orgs/:id` | Organization detail |
| `PUT` | `/orgs/:id` | Update organization |
| `POST` | `/orgs/:id/switch` | Switch active org |
| `POST` | `/orgs/:id/invite` | Invite user by email |
| `POST` | `/orgs/accept-invite` | Accept invitation |
| `DELETE` | `/orgs/:id/members/:uid` | Remove member |
| `PUT` | `/orgs/:id/members/:uid` | Update member role |

### Reports & Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/reports/generate` | Generate report (security/compliance/executive) |
| `GET` | `/reports` | List generated reports |
| `GET` | `/reports/:id` | Report detail |
| `DELETE` | `/reports/:id` | Delete report |

### Drift Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/drift/diffs` | List configuration diffs |
| `GET` | `/drift/diffs/summary` | Diff summary |
| `POST` | `/drift/diffs/:id/review` | Mark diff as reviewed |
| `GET` | `/drift/buckets/:id/history` | Bucket change history |
| `GET` | `/drift/scans/:job_id/diffs` | Diffs from a specific scan |

### Custom Alert Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/alert-rules` | Create alert rule |
| `GET` | `/alert-rules` | List rules |
| `GET` | `/alert-rules/:id` | Rule detail |
| `PUT` | `/alert-rules/:id` | Update rule |
| `DELETE` | `/alert-rules/:id` | Delete rule |
| `POST` | `/alert-rules/:id/toggle` | Enable/disable rule |
| `POST` | `/alert-rules/test` | Test rule against sample data |

### Remediation

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/remediations/bulk-status` | Bulk status update |
| `POST` | `/remediations/bulk-assign` | Bulk assign to user |
| `POST` | `/remediations/bulk-close` | Bulk close remediations |

### Audit & Activity

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/activity` | User activity feed |
| `GET` | `/audit-log` | Comprehensive audit log |
| `GET` | `/audit-log/entity/:type/:id` | Entity-specific audit trail |

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
| 403 | Account disabled or missing CSRF token |
| 404 | Resource not found |
| 409 | Conflict (duplicate email/username) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

---

## Real-Time Events (SSE)

```
GET /events/scans
```

| Event | Description |
|-------|-------------|
| `connected` | Connection established |
| `scan_started` | Scan job began |
| `progress` | Periodic progress update |
| `bucket_found` | New bucket discovered |
| `scan_complete` | Scan finished |
| `scan_cancelled` | Scan was cancelled |
| `error` | Scan error |
| `monitor_progress` | Watchlist scan progress |
| `monitor_complete` | Watchlist scan finished |

Keepalive: `: keepalive\n\n` every 15 seconds.

---

For complete request/response examples, authentication details, data objects, and webhook payload formats, see the **[full API reference](../API.md)**.
