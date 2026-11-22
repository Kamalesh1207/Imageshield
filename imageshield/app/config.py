"""Central configuration. Everything can be overridden with environment variables."""
from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.getenv("IMAGESHIELD_DATA", "./data")).resolve()
DB_PATH = DATA_DIR / "imageshield.db"
VAULT_DIR = DATA_DIR / "vault"

# Upload safety limits
MAX_UPLOAD_BYTES = int(os.getenv("IMAGESHIELD_MAX_BYTES", 15 * 1024 * 1024))
MAX_PIXELS = int(os.getenv("IMAGESHIELD_MAX_PIXELS", 50_000_000))
ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}

# Auth: comma separated list of API keys. CHANGE THIS before deploying.
# (Swap for OAuth/JWT + a users table in production.)
API_KEYS = {k.strip() for k in os.getenv("IMAGESHIELD_API_KEYS", "dev-key").split(",") if k.strip()}

# Basic in-memory rate limit (requests per minute per key). Use Redis in production.
RATE_LIMIT_PER_MIN = int(os.getenv("IMAGESHIELD_RATE_LIMIT", 60))

# Registry matching thresholds (Hamming distance on 64-bit perceptual hashes)
MATCH_NEAR_DUPLICATE = 6      # almost certainly the same picture (resize/recompress)
MATCH_DERIVED = 14            # likely edited / cropped / filtered derivative

# Video screening limits
MAX_VIDEO_BYTES = int(os.getenv("IMAGESHIELD_MAX_VIDEO_BYTES", 100 * 1024 * 1024))
MAX_VIDEO_SECONDS = int(os.getenv("IMAGESHIELD_MAX_VIDEO_SECONDS", 180))
VIDEO_SAMPLE_FRAMES = int(os.getenv("IMAGESHIELD_VIDEO_FRAMES", 16))

# Secret key for invisible watermarks (keeps the embedding pattern private). CHANGE IN PRODUCTION.
WM_KEY = os.getenv("IMAGESHIELD_WM_KEY", "dev-watermark-key").encode()

# Optional Hugging Face image-classification model id for AI-image detection.
HF_MODEL_ID = os.getenv("IMAGESHIELD_HF_MODEL", "")

# Optional path to a Haar cascade xml (used for face detection if OpenCV data is missing).
FACE_CASCADE_PATH = os.getenv("IMAGESHIELD_FACE_CASCADE", "")

CORS_ORIGINS = [o for o in os.getenv("IMAGESHIELD_CORS", "").split(",") if o]

DATA_DIR.mkdir(parents=True, exist_ok=True)
VAULT_DIR.mkdir(parents=True, exist_ok=True)
