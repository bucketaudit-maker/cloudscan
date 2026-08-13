# BucketAudit Railway Private Beta Deployment

This deployment runs four services in one Railway project:

- `postgres`: Railway PostgreSQL, private only
- `api`: Flask and Gunicorn, public
- `worker`: watchlist and recurring-scan schedulers, private only
- `frontend`: React and nginx, public

Keep the worker at exactly one replica. The current scheduler uses process-local
threads and is not designed for multiple worker replicas.

## 1. Create The Project

1. Create an empty Railway project.
2. Add a PostgreSQL database named `postgres`.
3. Add three empty services named `api`, `worker`, and `frontend`.
4. Connect each application service to the same GitHub repository and production branch.

Do not generate a public domain for PostgreSQL or `worker`.

## 2. Configure Service Sources

The repository root is directly deployable as the API. This supports Railway's
default GitHub service setup without requiring a root-directory override:

| Service | Root directory | Config file |
| --- | --- | --- |
| `api` | `/` | `/railway.json` |

For separate worker and frontend services, use the service-specific settings
below.

Use these settings for each service:

| Service | Root directory | Config file |
| --- | --- | --- |
| `worker` | `/backend` | `/backend/railway.worker.json` |
| `frontend` | `/frontend` | `/frontend/railway.json` |
| `scannerJob` | `/` | `/backend/railway.scanner.json` |

Set the config-file path under each service's Config as Code setting. The API
config runs `alembic upgrade head` before deploying and blocks the release if a
migration fails.

## 3. Configure Variables

Generate a production secret locally:

```bash
openssl rand -hex 32
```

Create `SECRET_KEY` as a shared Railway variable and share it with `api` and
`worker`.

Set these variables on `api`:

```dotenv
APP_ENV=production
DEBUG=false
DATABASE_URL=${{postgres.DATABASE_URL}}
SECRET_KEY=${{shared.SECRET_KEY}}
RUN_DB_MIGRATIONS_ON_STARTUP=false
ENABLE_MONITOR_SCHEDULER=false
ENABLE_SCAN_SCHEDULER=false
SCANNER_CONCURRENCY=20
SCANNER_TIMEOUT=15
GUNICORN_WORKERS=1
GUNICORN_THREADS=8
CORS_ORIGINS=https://${{frontend.RAILWAY_PUBLIC_DOMAIN}}
AI_ENABLED=false
```

Set these variables on `worker`:

```dotenv
APP_ENV=production
DEBUG=false
DATABASE_URL=${{postgres.DATABASE_URL}}
SECRET_KEY=${{shared.SECRET_KEY}}
RUN_DB_MIGRATIONS_ON_STARTUP=false
ENABLE_MONITOR_SCHEDULER=true
MONITOR_SCHEDULER_INTERVAL_SECONDS=300
ENABLE_SCAN_SCHEDULER=true
SCAN_SCHEDULER_INTERVAL_SECONDS=60
SCANNER_CONCURRENCY=20
SCANNER_TIMEOUT=15
AI_ENABLED=false
```

Set this build variable on `frontend`:

```dotenv
VITE_API_URL=https://${{api.RAILWAY_PUBLIC_DOMAIN}}
```

`VITE_API_URL` is compiled into the browser bundle. Redeploy `frontend` after
changing the API domain.

For a run-to-completion scanner service, set this single-line start command on
`scannerJob`:

```bash
python -m backend.app.scanners.engine -p aws azure gcp digitalocean alibaba -k assets uploads backup public static data config logs -c bucketaudit cloudscan -n 500 -r 3 --concurrency 15 --timeout 15
```

Reference the same `DATABASE_URL` used by the API. Do not configure public
networking or a health-check path for this service. The scanner config disables
restarts because a successful scan exits normally.

## 4. Deploy In Order

1. Deploy `postgres` and wait until it is healthy.
2. Generate a public Railway domain for `api`.
3. Generate a public Railway domain for `frontend`.
4. Confirm the cross-service variables resolve to those domains.
5. Deploy `api`; its pre-deploy migration must succeed.
6. Deploy `worker` with one replica.
7. Deploy `frontend`.

Verify the release:

```bash
curl -fsS https://YOUR_API_DOMAIN/api/v1/health
curl -I https://YOUR_FRONTEND_DOMAIN/
```

Then register a new account, run a small authorized scan, create a watchlist,
and confirm the worker logs show both schedulers starting.

## 5. Production Guardrails

- Only scan assets a customer owns or is explicitly authorized to assess.
- Start with a low scanner concurrency and monitor outbound traffic and costs.
- Never seed demo users or demo findings into production.
- Enable PostgreSQL backups before accepting customer data.
- Keep one API worker until SSE and active scan state are moved to Redis.
- Keep one scheduler worker until dispatch uses a durable queue and distributed lock.
- Add an AI provider key only after setting per-user quotas and cost limits.
- Use custom domains only after the Railway domains pass the smoke test.

## 6. Custom Domains

After the Railway-domain deployment is stable, configure:

- `app.bucketaudit.com` for `frontend`
- `api.bucketaudit.com` for `api`

Then update and redeploy:

```dotenv
# api
CORS_ORIGINS=https://app.bucketaudit.com

# frontend build variable
VITE_API_URL=https://api.bucketaudit.com
```

Railway provisions TLS certificates after DNS validation.
