"""Central configuration with fail-closed production secret handling."""
from __future__ import annotations

import os
from pathlib import Path

APP_ENV = os.getenv("IMAGESHIELD_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"

DATA_DIR = Path(os.getenv("IMAGESHIELD_DATA", "./data")).resolve()
DB_PATH = DATA_DIR / "imageshield.db"
VAULT_DIR = DATA_DIR / "vault"

# Upload safety limits
MAX_UPLOAD_BYTES = int(os.getenv("IMAGESHIELD_MAX_BYTES", 15 * 1024 * 1024))
MAX_PIXELS = int(os.getenv("IMAGESHIELD_MAX_PIXELS", 50_000_000))
ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}

# Shared API keys remain a temporary authentication mechanism. Never ship a default key.
_api_keys_raw = os.getenv("IMAGESHIELD_API_KEYS", "")
if IS_PRODUCTION and not _api_keys_raw.strip():
    raise RuntimeError("IMAGESHIELD_API_KEYS must be set in production; default credentials are disabled.")
API_KEYS = {k.strip() for k in _api_keys_raw.split(",") if k.strip()}
if IS_PRODUCTION and any(len(k) < 32 for k in API_KEYS):
    raise RuntimeError("Every production API key must contain at least 32 characters.")

# Basic in-memory rate limit (single-process protection only; use a shared limiter for multi-instance).
RATE_LIMIT_PER_MIN = int(os.getenv("IMAGESHIELD_RATE_LIMIT", 60))

# Registry matching thresholds
MATCH_NEAR_DUPLICATE = 6
MATCH_DERIVED = 14

# Video screening limits
MAX_VIDEO_BYTES = int(os.getenv("IMAGESHIELD_MAX_VIDEO_BYTES", 100 * 1024 * 1024))
MAX_VIDEO_SECONDS = int(os.getenv("IMAGESHIELD_MAX_VIDEO_SECONDS", 180))
VIDEO_SAMPLE_FRAMES = int(os.getenv("IMAGESHIELD_VIDEO_FRAMES", 16))

# Watermark secret must be explicitly configured in production.
_wm_key = os.getenv("IMAGESHIELD_WM_KEY", "")
if IS_PRODUCTION and len(_wm_key) < 32:
    raise RuntimeError("Set IMAGESHIELD_WM_KEY to a random secret of at least 32 characters in production.")
WM_KEY = (_wm_key or "dev-watermark-key").encode()

HF_MODEL_ID = os.getenv("IMAGESHIELD_HF_MODEL", "")
FACE_CASCADE_PATH = os.getenv("IMAGESHIELD_FACE_CASCADE", "")
CORS_ORIGINS = [o.strip() for o in os.getenv("IMAGESHIELD_CORS", "").split(",") if o.strip()]

DATA_DIR.mkdir(parents=True, exist_ok=True)
VAULT_DIR.mkdir(parents=True, exist_ok=True)
