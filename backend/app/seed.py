"""
Seed the database with realistic demo data for development/demo purposes.
Run: python -m backend.app.seed
"""
import hashlib
import os
import random
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.app.models.database import init_db, get_db, BucketStore, FileStore
from backend.app.utils.auth import hash_password, generate_api_key


def seed():
    init_db()

    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM buckets").fetchone()[0] > 0:
            print("Database already has data. Skipping seed.")
            return

    print("Seeding demo data...")

    # Create demo user
    with get_db() as db:
        db.execute("""
            INSERT OR IGNORE INTO users (email, username, password_hash, api_key, tier, created_at, queries_reset_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ("demo@cloudscan.io", "demo", hash_password("demo1234"),
              "cs_demo_key_for_testing_purposes_only", "premium",
              datetime.utcnow().isoformat(),
              (datetime.utcnow() + timedelta(days=1)).isoformat()))
    print("  Created demo user: demo@cloudscan.io / demo1234")

    # Realistic buckets across providers
    buckets_data = [
        # AWS S3
        (1, "company-backup-prod", "us-east-1", "https://company-backup-prod.s3.amazonaws.com", "open"),
        (1, "webapp-static-assets", "us-west-2", "https://webapp-static-assets.s3.us-west-2.amazonaws.com", "open"),
        (1, "data-lake-analytics", "eu-west-1", "https://data-lake-analytics.s3.eu-west-1.amazonaws.com", "open"),
        (1, "staging-db-exports", "us-east-1", "https://staging-db-exports.s3.amazonaws.com", "open"),
        (1, "media-uploads-2024", "ap-southeast-1", "https://media-uploads-2024.s3.ap-southeast-1.amazonaws.com", "open"),
        (1, "internal-docs-share", "us-east-1", "https://internal-docs-share.s3.amazonaws.com", "closed"),
        (1, "terraform-state-prod", "eu-central-1", "https://terraform-state-prod.s3.eu-central-1.amazonaws.com", "open"),
        (1, "customer-data-export", "us-west-1", "https://customer-data-export.s3.us-west-1.amazonaws.com", "closed"),
        (1, "dev-test-artifacts", "us-east-2", "https://dev-test-artifacts.s3.us-east-2.amazonaws.com", "open"),
        (1, "log-archive-2025", "us-east-1", "https://log-archive-2025.s3.amazonaws.com", "open"),
        (1, "ml-models-registry", "us-west-2", "https://ml-models-registry.s3.us-west-2.amazonaws.com", "open"),
        (1, "ci-cd-artifacts", "us-east-1", "https://ci-cd-artifacts.s3.amazonaws.com", "open"),
        # Azure Blob
        (2, "corpbackups", "", "https://corpbackups.blob.core.windows.net", "open"),
        (2, "websiteassets", "", "https://websiteassets.blob.core.windows.net", "open"),
        (2, "logstorage2024", "", "https://logstorage2024.blob.core.windows.net", "open"),
        (2, "devtestdata", "", "https://devtestdata.blob.core.windows.net", "closed"),
        (2, "publicmedia", "", "https://publicmedia.blob.core.windows.net", "open"),
        (2, "azuremldata", "", "https://azuremldata.blob.core.windows.net", "open"),
        # GCP
        (3, "analytics-export-prod", "", "https://storage.googleapis.com/analytics-export-prod", "open"),
        (3, "ml-training-data", "", "https://storage.googleapis.com/ml-training-data", "open"),
        (3, "static-site-hosting", "", "https://storage.googleapis.com/static-site-hosting", "open"),
        (3, "gcp-function-deploys", "", "https://storage.googleapis.com/gcp-function-deploys", "closed"),
        (3, "bigquery-exports", "", "https://storage.googleapis.com/bigquery-exports", "open"),
        # DigitalOcean
        (4, "app-uploads", "nyc3", "https://app-uploads.nyc3.digitaloceanspaces.com", "open"),
        (4, "cdn-static", "sfo3", "https://cdn-static.sfo3.digitaloceanspaces.com", "open"),
        (4, "db-backups-do", "ams3", "https://db-backups-do.ams3.digitaloceanspaces.com", "open"),
        # Alibaba
        (5, "oss-public-data", "cn-hangzhou", "https://oss-public-data.oss-cn-hangzhou.aliyuncs.com", "open"),
        (5, "app-resources-ali", "us-west-1", "https://app-resources-ali.oss-us-west-1.aliyuncs.com", "open"),
    ]

    file_templates = [
        ("{p}/config/{n}.json", "{n}.json", "json"),
        ("{p}/.env.{e}", ".env.{e}", "env"),
        ("{p}/secrets/{n}.json", "{n}.json", "json"),
        ("{p}/credentials.json", "credentials.json", "json"),
        ("{p}/config.yaml", "config.yaml", "yaml"),
        ("{p}/settings.ini", "settings.ini", "ini"),
        ("backups/{n}.sql", "{n}.sql", "sql"),
        ("backups/{n}-{d}.sql.gz", "{n}-{d}.sql.gz", "gz"),
        ("exports/{n}.csv", "{n}.csv", "csv"),
        ("exports/{n}.parquet", "{n}.parquet", "parquet"),
        ("docs/{n}.pdf", "{n}.pdf", "pdf"),
        ("docs/{n}.docx", "{n}.docx", "docx"),
        ("reports/{n}.xlsx", "{n}.xlsx", "xlsx"),
        ("scripts/{n}.sh", "{n}.sh", "sh"),
        ("deploy/{n}.py", "{n}.py", "py"),
        ("{p}/docker-compose.yml", "docker-compose.yml", "yml"),
        ("{p}/Dockerfile", "Dockerfile", ""),
        ("{p}/terraform.tfstate", "terraform.tfstate", "tfstate"),
        ("{p}/terraform.tfvars", "terraform.tfvars", "tfvars"),
        ("archives/{n}.zip", "{n}.zip", "zip"),
        ("archives/{n}.tar.gz", "{n}.tar.gz", "gz"),
        ("logs/{n}.log", "{n}.log", "log"),
        ("logs/{d}/access.log", "access.log", "log"),
        ("logs/{d}/error.log", "error.log", "log"),
        ("{p}/index.html", "index.html", "html"),
        ("assets/js/{n}.js", "{n}.js", "js"),
        ("assets/css/{n}.css", "{n}.css", "css"),
        ("{p}/server.key", "server.key", "key"),
        ("{p}/certificate.pem", "certificate.pem", "pem"),
        ("{p}/id_rsa", "id_rsa", ""),
        ("{p}/id_rsa.pub", "id_rsa.pub", "pub"),
        ("{p}/.htpasswd", ".htpasswd", "htpasswd"),
        ("{p}/wp-config.php", "wp-config.php", "php"),
        ("data/{n}.sqlite", "{n}.sqlite", "sqlite"),
        ("{p}/package.json", "package.json", "json"),
        ("{p}/requirements.txt", "requirements.txt", "txt"),
        ("{p}/Gemfile", "Gemfile", ""),
    ]

    names = ["database", "app", "api", "auth", "server", "production", "users", "orders",
             "analytics", "customers", "payments", "sessions", "products", "security-audit",
             "budget-forecast", "deploy", "migrate", "cleanup", "backup", "stripe-keys",
             "firebase-config", "aws-credentials", "master-key", "oauth-tokens"]
    envs = ["production", "staging", "development", "local", "test"]
    paths = ["", "data", "private", "admin", "internal", "2024", "2025", "v1", "v2", "config"]
    dates = ["2024-01-15", "2024-06-22", "2024-09-01", "2025-01-05", "2025-02-28"]

    now = datetime.utcnow()
    total_files = 0

    for pid, bname, region, url, status in buckets_data:
        bucket = BucketStore.upsert(pid, bname, region, url, status)
        if status != "open":
            continue

        num_files = random.randint(40, 200)
        files = []
        seen_paths = set()

        for _ in range(num_files):
            tpl = random.choice(file_templates)
            fp_t, fn_t, ext = tpl
            n = random.choice(names)
            p = random.choice(paths)
            e = random.choice(envs)
            d = random.choice(dates)

            fp = fp_t.format(n=n, p=p, e=e, d=d).lstrip("/")
            if fp in seen_paths:
                continue
            seen_paths.add(fp)

            fn = fn_t.format(n=n, e=e, d=d)

            files.append({
                "filepath": fp,
                "filename": fn,
                "extension": ext,
                "size_bytes": random.randint(64, 80_000_000),
                "last_modified": (now - timedelta(days=random.randint(1, 400))).isoformat(),
                "etag": hashlib.md5(fp.encode()).hexdigest(),
                "content_type": "",
                "url": f"{url.rstrip('/')}/{fp}",
            })

        FileStore.insert_batch(bucket["id"], files)
        total_files += len(files)
        print(f"  {bname}: {len(files)} files")

    print(f"\nSeeded {len(buckets_data)} buckets, {total_files} files")
    print("Demo API key: cs_demo_key_for_testing_purposes_only")


if __name__ == "__main__":
    seed()
