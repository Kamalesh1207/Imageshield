# ImageShield deployment readiness

## Hackathon prototype
**Prototype deployment configuration is prepared; the Render service has not been created or deployed yet.**

The `render.yaml` Blueprint defines one free Singapore web service. It serves the bundled frontend and FastAPI API from the same origin. The service is configured for a production-mode startup with explicit secrets and a health check.

Prototype limitations:
- Shared API-key authentication only. This is for a controlled demo, not a public multi-user service.
- SQLite and encrypted evidence files use the service filesystem. Render free filesystem is ephemeral; data may be lost on restart/redeploy.
- Do not upload real, sensitive, or legally important evidence.
- Free service may sleep while idle.
- Image/video screening is indicative, not proof or legal evidence.

## Implemented on `production-hardening`
- Production startup refuses missing/short API keys and watermark secret.
- Production requires a stable Fernet evidence-vault key.
- Security response headers and tighter CORS defaults.
- Upload reads are bounded by configured size limits.
- Root dashboard can be served by FastAPI from the bundled frontend.
- Hosted frontend defaults to same-origin API and no longer silently fills in the development API key.
- Render Blueprint and hackathon setup guide.

## Remaining steps to get the prototype online
1. Open the Render Blueprint plan and apply the one free web service.
2. Set `IMAGESHIELD_API_KEYS`, `IMAGESHIELD_WM_KEY`, and `IMAGESHIELD_VAULT_KEY` directly in Render's Environment settings. Keep the values private.
3. Wait for the deploy to become Live, then open the generated `.onrender.com` URL.
4. Paste the API key into the dashboard's Server connection settings and test with non-sensitive sample files.

## Required before genuine public production
1. PostgreSQL adapter and tested migrations. Current database adapter is SQLite-specific.
2. Private durable object storage for encrypted evidence (e.g. Cloudflare R2), backups and key management.
3. Individual email/password accounts and Google OAuth with server-side token verification.
4. Per-user tenant isolation on every protected route; retire shared API-key auth.
5. Secure revocable sessions, CSRF protection, shared rate limiting and audit logs.
6. Malware scanning and stronger isolation for untrusted video processing.
7. Integration tests for authentication, tenant isolation, database, object storage, upload limits, backup/restore and deployment.
8. Privacy/retention policy and security/legal review.

Never put provider credentials or generated secrets in source control, screenshots, or public chat.
