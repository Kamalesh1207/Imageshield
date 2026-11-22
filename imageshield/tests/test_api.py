"""End-to-end API smoke test. Needs: pip install fastapi httpx (skipped automatically otherwise)."""
import io

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from PIL import Image  # noqa: E402

from app.main import app  # noqa: E402

H = {"X-API-Key": "test-key"}


def jpeg() -> bytes:
    b = io.BytesIO()
    Image.effect_noise((320, 240), 40).convert("RGB").save(b, "JPEG")
    return b.getvalue()


def test_auth_required_and_full_flow():
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200
        assert c.post("/v1/analyze", files={"file": ("a.jpg", jpeg(), "image/jpeg")}).status_code == 401

        r = c.post("/v1/analyze", headers=H, files={"file": ("a.jpg", jpeg(), "image/jpeg")})
        assert r.status_code == 200 and "verdict" in r.json()

        assert c.post("/v1/analyze", headers=H, files={"file": ("a.jpg", b"junk", "image/jpeg")}).status_code == 400

        case = c.post("/v1/cases", headers=H, json={"title": "t", "platform": "instagram"}).json()
        ev = c.post(f"/v1/cases/{case['id']}/evidence", headers=H, data={"note": "n"},
                    files={"file": ("a.jpg", jpeg(), "image/jpeg")})
        assert ev.status_code == 201
        assert c.get(f"/v1/cases/{case['id']}/verify", headers=H).json()["ok"] is True
        assert c.get(f"/v1/cases/{case['id']}/export", headers=H).headers["content-type"] == "application/zip"
        assert c.get("/v1/reporting/guide?platform=whatsapp&country=IN", headers=H).json()["steps"]
        assert c.post("/v1/risk/assess", headers=H, json={"profile_public": True}).json()["score"] > 0
