# ImageShield AI 2.0 - backend

Personal image misuse early-warning & digital evidence assistant (FastAPI + SQLite).

## Run
```bash
pip install -r requirements.txt
export IMAGESHIELD_API_KEYS="change-me"          # comma separated
export IMAGESHIELD_VAULT_KEY="$(python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"
uvicorn app.main:app --reload                     # docs at http://127.0.0.1:8000/docs
pytest -q                                         # API test auto-skips if fastapi/httpx are missing
```
Send `X-API-Key: change-me` on every `/v1/*` call.

## Feature -> endpoint map
| Concept-card feature | Endpoint(s) | Module |
|---|---|---|
| 1. Misuse risk assessment | `POST /v1/risk/assess`, `/v1/risk/assess-with-image` | `services/risk.py` |
| 2. AI-generated / manipulated screening | `POST /v1/analyze` (`?include_heatmap=true`) | `forensics.py`, `detector.py` |
| 3. Source & metadata analysis | included in `/v1/analyze` (`metadata`, `ai_signatures`, C2PA flag) | `metadata.py` |
| 4. Privacy risk alerts | `/v1/analyze` -> `privacy_alerts`; `GET /v1/alerts`; `POST /v1/privacy/scrub` | `alerts.py` |
| 5. Safe evidence organisation | `/v1/cases`, `/v1/cases/{id}/evidence`, `/verify`, `/export` | `evidence.py` |
| 6. Step-by-step reporting | `GET /v1/reporting/guide`, `/v1/cases/{id}/report-draft` | `reporting.py` |
| Extra: video deepfake screening | `POST /v1/analyze/video` | `video.py` |
| Extra: invisible watermark | `POST /v1/watermark/embed`, `/v1/watermark/detect` (also auto-checked in `/v1/analyze`) | `watermark.py` |
| Extra: protected-photo registry | `/v1/protect/register`, `/check`, list | `registry.py`, `hashing.py` |

## Design choices
* **Explainable verdicts**: separate `ai_generated_likelihood` and `tampering_likelihood`, with plain-language `reasons`, `confidence` and `limitations`. Heuristics alone are capped at low confidence.
* **Declared provenance first**: IPTC `trainedAlgorithmicMedia`, C2PA presence, Stable Diffusion / ComfyUI chunks.
* **Plug-in ML**: set `IMAGESHIELD_HF_MODEL` to a Hugging Face image-classification model id (install `transformers torch`). Evaluate it on your own data first.
* **Privacy by design**: registry stores only 64-bit hashes; GPS is echoed rounded to ~1 km; evidence is Fernet-encrypted at rest; files stored under random names; case lookups return 404 for other users' cases.
* **Minor safety**: sexual images of under-18s are never archived (`file_stored=false`); guidance routes to hash-based takedown and police.
* **Tamper-evident evidence**: per-case SHA-256 hash chain, verify endpoint, ZIP export with chain-of-custody.

## Before production
JWT/OAuth + user table instead of API keys - Postgres - object storage + KMS key - Redis rate limiting - malware scanning of uploads - virus/size limits at the proxy - background workers for heavy analysis - audit logging - legal review of reporting links/wording.

## Watermark: what it survives (measured on test images)
JPEG recompression down to ~q60, mild noise, ~35% of the frame replaced (face-swap-like), cropping (offset search). **Not** heavy resizing/rotation or a determined attacker. Set `IMAGESHIELD_WM_KEY` to a long secret and never lose it - without it old watermarks cannot be read.

## Video screening notes
Samples up to `IMAGESHIELD_VIDEO_FRAMES` frames + a temporal sharpness-flicker check. Confidence is "low" unless the file declares AI provenance. Audio/voice-clone detection and URL-based video fetching are not included (SSRF risk). Decode untrusted video in a sandboxed worker.

## Next steps (not implemented)
Audio deepfake detection, watermarking video frames, reverse-image-search integrations, consent-based face matching, mobile push for alerts, async job queue for long videos.


## Frontend dashboard
A responsive frontend is included in `frontend/`. Start the backend as above, then in a second terminal run:

```bash
python -m http.server 5500 --directory frontend
```

Open `http://127.0.0.1:5500`, go to **Server connection**, set the backend URL (default `http://127.0.0.1:8000`) and the same API key configured in `IMAGESHIELD_API_KEYS`. For cross-origin access, set `IMAGESHIELD_CORS=http://127.0.0.1:5500` when starting the backend. See `frontend/README.md` for details.
