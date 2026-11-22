# ImageShield AI — hackathon demo deployment

This Blueprint deploys the FastAPI backend and bundled dashboard as one Render web service in Singapore.

## Demo-only limitations

- This is a **hackathon prototype**, not a public multi-user production service.
- Authentication is a shared API key entered in the browser's Server connection page. Anyone given the key can use the demo API; do not distribute it publicly.
- The service uses SQLite and local encrypted evidence files. Render's free service filesystem is ephemeral, so database rows and evidence files can disappear after a restart or redeploy. Do not upload real, sensitive, or legally important evidence.
- Free instances may sleep when idle and take time to wake.
- Analysis results are indicative screening only, not proof that an image is AI-generated or manipulated and not legal evidence.

## Render setup

1. In Render, create a new Blueprint from this repository and select the `production-hardening` branch (or merge the PR and use `main`).
2. Review the single free web service named `imageshield-ai-demo` in Singapore.
3. Set the three secret environment variables when prompted:
   - `IMAGESHIELD_API_KEYS`: a long random API key (at least 32 characters; use 64 random hex characters).
   - `IMAGESHIELD_WM_KEY`: a separate random secret of at least 32 characters.
   - `IMAGESHIELD_VAULT_KEY`: a valid Fernet key. Generate locally with:
     ```bash
     python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
     ```
   Keep these values private. Never commit them to GitHub or paste them into public screenshots.
4. Apply the Blueprint and wait for the deploy to become Live.
5. Open the generated `.onrender.com` URL. In **Server connection**, keep the API URL as the same site, paste the API key, and save settings.
6. Check that the dashboard reports the server online and test with non-sensitive sample images.

## Before a genuine public launch

Replace shared API-key authentication with individual accounts (email/password and Google OAuth), secure sessions and CSRF protection; migrate SQLite to managed PostgreSQL; move encrypted evidence to private durable object storage (e.g. Cloudflare R2) with key management and backups; add shared rate limiting, audit logs, malware scanning, tenant-isolation tests, monitoring, privacy/retention policy, and security/legal review. Complete integration and recovery tests before accepting real user data.
