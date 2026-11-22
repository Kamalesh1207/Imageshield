# ImageShield production readiness

**Status: not ready for public production.**

Completed on this branch:
- Production requires explicit API keys and a 32+ character watermark secret.
- Production now requires a stable `IMAGESHIELD_VAULT_KEY`; the app will not silently create a disposable encryption key in production.
- Repository ignores local databases, encrypted evidence, local secrets and Python caches.

Remaining blockers:
1. PostgreSQL adapter and migrations. Current SQL adapter is SQLite-specific.
2. Private Cloudflare R2 evidence storage. Evidence currently resides on the local filesystem.
3. Email/password registration and Google OAuth with server-side token verification.
4. Per-user ownership on every protected route; retire shared API-key auth for multi-user public access.
5. Shared rate limiting, session/CSRF protections and security headers.
6. Integration tests for auth, tenant isolation, PostgreSQL, R2, uploads and deployment.

Do not deploy publicly until these are implemented and tested. Do not place provider credentials in source control or chat.
