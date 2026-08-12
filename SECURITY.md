# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

We take the security of BucketAudit seriously. If you discover a security vulnerability, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email: Send details to **bucketaudit@gmail.com**
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Assessment**: Within 5 business days, we will assess severity and impact
- **Resolution**: Critical vulnerabilities are patched within 7 days; others within 30 days
- **Credit**: With your permission, we will credit you in our changelog

### Scope

The following are in scope:
- Authentication and authorization bypass
- SQL injection, XSS, CSRF vulnerabilities
- Server-side request forgery (SSRF)
- Sensitive data exposure
- Remote code execution

The following are out of scope:
- Denial of service (DoS) attacks
- Social engineering
- Physical security
- Issues in third-party dependencies (report upstream)

## Security Best Practices for Deployment

1. **Always change default credentials** before deploying to production
2. **Set a strong `SECRET_KEY`** (minimum 32 characters, randomly generated)
3. **Use HTTPS** in production (configure TLS at your reverse proxy)
4. **Restrict CORS origins** to your specific domain
5. **Enable database SSL** for PostgreSQL connections
6. **Run behind a reverse proxy** (nginx) with rate limiting enabled
7. **Keep dependencies updated** and monitor for CVEs
