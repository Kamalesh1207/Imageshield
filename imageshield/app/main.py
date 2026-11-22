"""ImageShield AI 2.0 - backend API.  Run:  uvicorn app.main:app --reload"""
from __future__ import annotations

import hashlib
import hmac
import io
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import ValidationError

from . import config, db
from .schemas import CaseCreate, EvidenceMeta, RiskQuestionnaire
from .services import alerts as alerts_svc
from .services import evidence, hashing, pipeline, registry, reporting, risk, video, watermark
from .services.imaging import ImageError, load_image


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="ImageShield AI 2.0", version="2.0.0", lifespan=lifespan,
              description="Personal image misuse early-warning & digital evidence assistant.")
if config.CORS_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])


# ------------------------------------------------------------------ auth + rate limit
_hits: dict[str, deque] = defaultdict(deque)


def current_owner(x_api_key: str = Header(default="")) -> str:
    if not any(hmac.compare_digest(x_api_key, k) for k in config.API_KEYS):
        raise HTTPException(401, "Invalid or missing X-API-Key.")
    owner = hashlib.sha256(x_api_key.encode()).hexdigest()[:16]  # pseudonymous owner id
    now, q = time.monotonic(), _hits[owner]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= config.RATE_LIMIT_PER_MIN:
        raise HTTPException(429, "Too many requests. Slow down.")
    q.append(now)
    return owner


@app.exception_handler(ImageError)
@app.exception_handler(evidence.EvidenceError)
async def _domain_errors(_: Request, exc):
    return JSONResponse({"detail": str(exc)}, status_code=exc.status)


def _read_upload(f: UploadFile, limit: int | None = None) -> bytes:
    limit = limit or config.MAX_UPLOAD_BYTES
    data = f.file.read(limit + 1)  # bounded read: never trust Content-Length
    if len(data) > limit:
        raise ImageError("File too large.", 413)
    return data


# ------------------------------------------------------------------ health
@app.get("/health")
def health():
    return {"status": "ok"}


# ------------------------------------------------------------------ 2,3,4: analysis
@app.post("/v1/analyze")
def analyze(file: UploadFile = File(...), include_heatmap: bool = Query(False), owner: str = Depends(current_owner)):
    """AI/manipulation screening + metadata/source analysis + privacy alerts + registry match."""
    return pipeline.full_analysis(owner, _read_upload(file), include_heatmap)


@app.post("/v1/analyze/video")
def analyze_video(file: UploadFile = File(...), owner: str = Depends(current_owner)):
    """Deepfake / AI screening for a video upload (sampled frames + temporal check)."""
    return video.analyze_video(_read_upload(file, config.MAX_VIDEO_BYTES))


@app.post("/v1/watermark/embed")
def watermark_embed(file: UploadFile = File(...), label: str = Form("", max_length=80),
                    strength: float = Form(20.0, ge=12.0, le=40.0), owner: str = Depends(current_owner)):
    """Embed an invisible, keyed ID into a photo before publishing. Returns the watermarked image
    (JPEG in -> JPEG q95 out, otherwise PNG) with the ID in the X-Watermark-Id header."""
    img, fmt = load_image(_read_upload(file))
    try:
        wm_id = watermark.new_id()
        marked = watermark.embed(img, wm_id, config.WM_KEY, strength)
    except watermark.WatermarkError as e:
        raise HTTPException(422, str(e))
    registry.register_watermark(owner, label or None, wm_id)
    buf = io.BytesIO()
    if fmt == "JPEG":
        marked.save(buf, "JPEG", quality=95)
        mime, ext = "image/jpeg", "jpg"
    else:
        marked.save(buf, "PNG")
        mime, ext = "image/png", "png"
    return Response(buf.getvalue(), media_type=mime, headers={
        "X-Watermark-Id": wm_id, "Content-Disposition": f'attachment; filename="protected.{ext}"'})


@app.post("/v1/watermark/detect")
def watermark_detect(file: UploadFile = File(...), strength: float = Form(20.0, ge=12.0, le=40.0),
                     owner: str = Depends(current_owner)):
    """Look for an ImageShield watermark (searches crops/offsets). Details are shown only to the owner."""
    img, _ = load_image(_read_upload(file))
    return pipeline.describe_watermark(owner, watermark.detect(img, config.WM_KEY, strength, full_search=True))


@app.post("/v1/privacy/scrub")
def scrub(file: UploadFile = File(...), owner: str = Depends(current_owner)):
    """Return the image with all metadata (GPS, serials, thumbnails...) removed."""
    img, fmt = load_image(_read_upload(file))
    out, mime = alerts_svc.scrub_metadata(img, fmt)
    ext = {"image/png": "png", "image/webp": "webp"}.get(mime, "jpg")
    return Response(out, media_type=mime, headers={"Content-Disposition": f'attachment; filename="clean.{ext}"'})


@app.get("/v1/alerts")
def get_alerts(unread_only: bool = True, owner: str = Depends(current_owner)):
    sql = "SELECT * FROM alerts WHERE owner=?" + (" AND is_read=0" if unread_only else "") + " ORDER BY id DESC LIMIT 200"
    return [dict(r) for r in db.query(sql, (owner,))]


@app.post("/v1/alerts/read-all")
def mark_alerts_read(owner: str = Depends(current_owner)):
    with db.tx() as c:
        c.execute("UPDATE alerts SET is_read=1 WHERE owner=?", (owner,))
    return {"ok": True}


# ------------------------------------------------------------------ 1: protected registry + risk
@app.post("/v1/protect/register")
def protect_register(file: UploadFile = File(...), label: str = Form("", max_length=80),
                     owner: str = Depends(current_owner)):
    """Register one of YOUR photos (only hashes are stored) so altered copies can be recognised later."""
    data = _read_upload(file)
    img, _ = load_image(data)
    return registry.register(owner, label or None, hashing.fingerprints(img, data))


@app.get("/v1/protect")
def protect_list(owner: str = Depends(current_owner)):
    return registry.list_registered(owner)


@app.post("/v1/protect/check")
def protect_check(file: UploadFile = File(...), owner: str = Depends(current_owner)):
    data = _read_upload(file)
    img, _ = load_image(data)
    return {"matches": registry.find_matches(owner, hashing.fingerprints(img, data))}


@app.post("/v1/risk/assess")
def risk_assess(q: RiskQuestionnaire, owner: str = Depends(current_owner)):
    return risk.assess(q)


@app.post("/v1/risk/assess-with-image")
def risk_assess_with_image(file: UploadFile = File(...), questionnaire_json: str = Form("{}"),
                           owner: str = Depends(current_owner)):
    try:
        q = RiskQuestionnaire.model_validate_json(questionnaire_json)
    except ValidationError as e:
        raise HTTPException(422, e.errors(include_url=False, include_context=False))
    analysis = pipeline.full_analysis(owner, _read_upload(file))
    return {"risk": risk.assess(q, analysis, analysis["registry_matches"]), "image_verdict": analysis["verdict"]}


# ------------------------------------------------------------------ 5: cases + evidence vault
@app.post("/v1/cases", status_code=201)
def create_case(body: CaseCreate, owner: str = Depends(current_owner)):
    return evidence.create_case(owner, body.title, body.platform, body.content_type, body.is_minor)


@app.get("/v1/cases")
def cases(owner: str = Depends(current_owner)):
    return evidence.list_cases(owner)


@app.post("/v1/cases/{case_id}/evidence", status_code=201)
def add_evidence(case_id: str, file: UploadFile | None = File(None), kind: str = Form("screenshot"),
                 source_url: str | None = Form(None), platform: str | None = Form(None),
                 note: str | None = Form(None), record_only: bool = Form(False),
                 owner: str = Depends(current_owner)):
    """Upload a screenshot/image as evidence. record_only=true stores just URL/time/note (no file) -
    use it for sexual images of minors, which must not be copied or archived."""
    try:
        meta = EvidenceMeta(kind=kind, source_url=source_url or None, platform=platform or None, note=note)
    except ValidationError as e:
        raise HTTPException(422, e.errors(include_url=False, include_context=False))
    if record_only or file is None:
        return evidence.add_evidence(owner, case_id, None, kind=meta.kind, source_url=str(meta.source_url or "") or None,
                                     platform=meta.platform, note=meta.note, store_file=False)
    data = _read_upload(file)
    img, fmt = load_image(data)  # validates it really is an image
    analysis = pipeline.full_analysis(owner, data)
    analysis.pop("ela_heatmap_png_b64", None)
    mime = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp"}[fmt]
    return evidence.add_evidence(owner, case_id, data, mime=mime, kind=meta.kind,
                                 source_url=str(meta.source_url) if meta.source_url else None,
                                 platform=meta.platform, note=meta.note, analysis=analysis)


@app.get("/v1/cases/{case_id}/evidence")
def list_evidence(case_id: str, owner: str = Depends(current_owner)):
    return evidence.list_evidence(owner, case_id)


@app.get("/v1/cases/{case_id}/verify")
def verify_case(case_id: str, owner: str = Depends(current_owner)):
    return evidence.verify_chain(owner, case_id)


@app.get("/v1/cases/{case_id}/export")
def export_case(case_id: str, owner: str = Depends(current_owner)):
    return Response(evidence.export_zip(owner, case_id), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="imageshield_case_{case_id[:8]}.zip"'})


@app.get("/v1/cases/{case_id}/report-draft", response_class=PlainTextResponse)
def report_draft(case_id: str, country: str = "IN", owner: str = Depends(current_owner)):
    case = evidence.get_case(owner, case_id)
    return reporting.draft_complaint(case, evidence.list_evidence(owner, case_id), country)


# ------------------------------------------------------------------ 6: reporting guidance
@app.get("/v1/reporting/guide")
def reporting_guide(platform: str = "other", country: str = "IN", content_type: str = "ai_generated_or_edited",
                    is_minor: bool = False, owner: str = Depends(current_owner)):
    return reporting.guide(platform, country, content_type, is_minor)
