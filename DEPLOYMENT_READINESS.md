# ImageShield AI — deployment readiness

## Current status

This branch is a safety-hardening work branch. It is **not yet ready for public production deployment**.

The current application still uses:
- SQLite for application records (the current SQL layer is SQLite-specific).
- Local filesystem storage for encrypted evidence files.
- Shared API-key authentication (no user registration, email/password login, or Google OAuth flow yet).
- In-process rate limiting (not shared across multiple service instances).

The Render free filesystem is ephemeral, so deploying this version as-is could lose uploaded evidence and local database contents after a restart or redeploy. Do not deploy it as a production evidence vault.

## Required work before public production

1. Replace the SQLite-specific data layer with a tested PostgreSQL implementation and migrations.
2. Move encrypted evidence objects to a private S3-compatible bucket (Cloudflare R2); keep object keys private and serve downloads only after owner authorization.
3. Implement account-based authentication (email/password with secure password hashing, Google OAuth, account ownership, session/token expiry, logout, and CSRF/CORS protections).
4. Replace shared API-key ownership with authenticated user IDs on every protected route.
5. Add shared rate limiting, security headers, strict upload validation, and automated authorization/isolation tests.
6. Configure provider secrets in Render's environment settings. Never commit credentials or paste them into chat.
7. Run database, storage, auth, upload, and deployment smoke tests before enabling public access.

## Temporary production fail-closed checks

When `IMAGESHIELD_ENV=production`, the application now refuses to start unless:
- `IMAGESHIELD_API_KEYS` is explicitly set and every key is at least 32 characters.
- `IMAGESHIELD_WM_KEY` is explicitly set and at least 32 characters.

These checks prevent accidental use of the repository's development defaults. They do **not** turn API-key authentication into multi-user authentication.

## Local development

Leave `IMAGESHIELD_ENV` unset (or set it to `development`) for the existing local prototype workflow.
