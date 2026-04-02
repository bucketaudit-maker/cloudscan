# Privacy Policy

**Last updated:** April 2026

## Overview

CloudScan is an open-source cloud storage security tool. This policy describes how data is collected, used, and stored when you self-host CloudScan.

## Data We Process

### Bucket Metadata
- Bucket names, URLs, regions, and provider information
- Bucket access status (open/closed/partial)
- File listings (names, sizes, types) from publicly accessible buckets

### User Data
- Email address and hashed password (for account authentication)
- API usage logs (endpoint, timestamp, IP address for rate limiting)
- User preferences and settings

### What We Do NOT Collect
- Contents of files inside buckets (only metadata)
- Personal data from discovered buckets
- Analytics or telemetry sent to third parties

## Data Storage

All data is stored in your self-hosted PostgreSQL database. CloudScan does not transmit data to external servers except:
- **AI providers** (optional): If configured, bucket file lists may be sent to OpenAI, Anthropic, or Google for AI-powered classification. Disable `AI_ENABLED` to prevent this.
- **Cloud provider APIs**: DNS and HTTP requests are made to cloud providers (AWS, GCP, Azure, etc.) during bucket scanning.

## Data Retention

- Bucket and file metadata: Retained until manually deleted
- API logs: Retained for 90 days by default
- Scan results: Retained until manually deleted
- User sessions: JWT tokens expire after 24 hours

## Your Rights

Since CloudScan is self-hosted, you have full control over your data:
- **Access**: Query your database directly
- **Delete**: Remove any data via the API or database
- **Export**: Use the API to export all data
- **Portability**: Your database is yours; back up and migrate freely

## Security

See [SECURITY.md](./SECURITY.md) for our security policy and best practices.

## Responsible Use

CloudScan is designed for legitimate security research and authorized asset monitoring. Users are responsible for ensuring their use complies with applicable laws, cloud provider terms of service, and ethical standards.

**Company attributions** shown in the UI are pattern-based and unverified. They indicate which company keyword generated a bucket name pattern, not confirmed ownership.

## Contact

For privacy concerns, contact: **privacy@cloudscan.dev**
