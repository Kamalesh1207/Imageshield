# ImageShield AI frontend

A responsive, dependency-free frontend for the ImageShield AI 2.0 FastAPI backend.

## Start the backend
From the `imageshield/` project directory:

```bash
pip install -r requirements.txt
# Development key is `dev-key` unless you set your own.
IMAGESHIELD_API_KEYS=dev-key uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Start the frontend
Serve the `frontend/` directory using any static HTTP server. For example:

```bash
python -m http.server 5500 --directory frontend
```

Open `http://127.0.0.1:5500`. In **Server connection**, set the backend URL and the same API key configured in `IMAGESHIELD_API_KEYS`.

You can also open `index.html` directly, but using a local HTTP server is recommended. If the frontend is hosted on a different origin, configure backend CORS before making API requests:

```bash
IMAGESHIELD_CORS=http://127.0.0.1:5500 uvicorn app.main:app --reload
```

For a hosted deployment, set `IMAGESHIELD_CORS` to the exact frontend origin and use HTTPS. Do not use the development API key or default watermark key in production. The API key is stored in this browser's local storage; this is suitable only for a personal prototype, not a public multi-user deployment.

## Connected features

- `GET /health` connection status
- `POST /v1/analyze` image analysis (optional heatmap)
- `POST /v1/analyze/video` video screening
- `POST /v1/risk/assess` risk questionnaire
- `POST /v1/protect/register`, `GET /v1/protect`, `POST /v1/protect/check`
- `POST /v1/watermark/embed`, `POST /v1/watermark/detect`
- `POST /v1/privacy/scrub`
- `GET /v1/alerts`, `POST /v1/alerts/read-all`
- `POST /v1/cases`, `GET /v1/cases`, case evidence, verification, export and report-draft endpoints
- `GET /v1/reporting/guide`

The frontend calls the existing API; it does not simulate successful server operations. Screening is indicative and should not be treated as forensic or legal proof.
