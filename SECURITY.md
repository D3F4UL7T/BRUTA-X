# Security

- Deny-by-default RBAC (`app/services/rbac.py`)
- Passwords: PBKDF2-HMAC-SHA256, 120k iterations, per-user salt
- Sessions: random token, SHA-256 stored
- API: off by default, localhost bind only, Bearer token, rate limit
- Webhooks: HTTPS only, block private/metadata ranges
- Audit/notifications/AI: secret field redaction
- Plugins: explicit enable, permission allow-list
- Scans: authorization checkboxes + asset authorized scope
- No credential theft features

**Limits:** Local multi-user is not a hardened multi-tenant server. Protect the host OS account.
