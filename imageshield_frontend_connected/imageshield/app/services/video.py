"""Video deepfake screening.

Samples frames evenly across the clip, runs the same forensic + fusion pipeline used for photos on
each frame, then adds a temporal check (frame-to-frame sharpness flicker, common in face-swaps).
Video compression destroys many forensic cues, so confidence is deliberately LOW unless the
container declares AI provenance (IPTC / C2PA strings).

SECURITY: decoding untrusted video means running FFmpeg code on attacker-controlled bytes. In
production run this in a sandboxed worker (container with no network, seccomp, CPU/memory/time limits).
Not supported: fetching a video from a URL (SSRF risk) - have the client upload the file.
"""
from __future__ import annotations

import os
import tempfile

import cv2
import numpy as np
from PIL import Image

from .. import config
from . import detector, forensics, metadata
from .imaging import ImageError

LIMITATIONS = [
    "Video compression removes many forensic traces; reliability is lower than for still photos.",
    "Only a sample of frames is analysed - brief manipulated segments can be missed.",
    "Audio (voice cloning / lip-sync) is NOT analysed.",
    "A clean result does not prove a video is authentic; findings are indicative, not conclusive.",
]


class VideoError(ImageError):
    pass


def _container_ok(head: bytes) -> bool:
    return (head[4:8] == b"ftyp"                                        # MP4 / MOV
            or head[:4] == b"\x1a\x45\xdf\xa3"                          # WebM / MKV
            or (head[:4] == b"RIFF" and head[8:12] == b"AVI "))         # AVI


def _clamp(x: float) -> float:
    return float(max(0.0, min(1.0, x)))


def _prep(bgr: np.ndarray) -> Image.Image:
    h, w = bgr.shape[:2]
    s = 960 / max(h, w)
    if s < 1:
        bgr = cv2.resize(bgr, (int(w * s), int(h * s)), interpolation=cv2.INTER_AREA)
    return Image.fromarray(cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB))


def _sharpness(bgr: np.ndarray) -> float:
    g = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    s = 480 / max(g.shape)
    if s < 1:
        g = cv2.resize(g, None, fx=s, fy=s, interpolation=cv2.INTER_AREA)
    return float(cv2.Laplacian(g, cv2.CV_64F).var())


def _flicker(cap: cv2.VideoCapture, n: int) -> float | None:
    """Median relative sharpness change between consecutive frames, over 3 short windows."""
    if n < 24:
        return None
    meds = []
    for frac in (0.15, 0.5, 0.85):
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(frac * (n - 9)))
        vals = []
        for _ in range(8):
            ok, f = cap.read()
            if not ok:
                break
            vals.append(_sharpness(f))
        if len(vals) >= 6:
            meds.append(float(np.median(np.abs(np.diff(vals)) / (np.mean(vals) + 1e-6))))
    return float(np.median(meds)) if meds else None


def analyze_video(data: bytes) -> dict:
    if len(data) > config.MAX_VIDEO_BYTES:
        raise VideoError("Video too large.", 413)
    if not _container_ok(data[:16]):
        raise VideoError("Unsupported video container. Use MP4/MOV, WebM/MKV or AVI.", 415)
    sigs, c2pa = metadata.scan_signatures(data)
    strong = [s for s in sigs if s["strength"] == "strong"]

    with tempfile.TemporaryDirectory(prefix="imageshield_") as tmp:
        path = os.path.join(tmp, "upload.video")
        with open(path, "wb") as fh:
            fh.write(data)
        cap = cv2.VideoCapture(path)
        try:
            n = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            fps = float(cap.get(cv2.CAP_PROP_FPS) or 0)
            w, h = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
            if not cap.isOpened() or n <= 0 or fps <= 0 or w <= 0:
                raise VideoError("Could not read this video.")
            duration = n / fps
            if duration > config.MAX_VIDEO_SECONDS:
                raise VideoError(f"Video longer than {config.MAX_VIDEO_SECONDS}s limit.", 413)
            if w * h > 4096 * 2304:
                raise VideoError("Video resolution too large.", 413)

            frames = []
            stub = {"ai_signatures": [], "flags": [], "software": None, "content_credentials_present": False}
            for idx in np.unique(np.linspace(0, n - 1, min(config.VIDEO_SAMPLE_FRAMES, n)).astype(int)):
                cap.set(cv2.CAP_PROP_POS_FRAMES, int(idx))
                ok, bgr = cap.read()
                if not ok:
                    continue
                v = detector.fuse(stub, forensics.run_all(_prep(bgr), jpeg_like=False), None)
                frames.append({"frame_index": int(idx), "time_s": round(idx / fps, 2),
                               "ai_likelihood": v["ai_generated_likelihood"],
                               "tampering_likelihood": v["tampering_likelihood"]})
            if not frames:
                raise VideoError("No frames could be decoded.")
            flicker = _flicker(cap, n)
        finally:
            cap.release()

    ai_p75 = float(np.percentile([f["ai_likelihood"] for f in frames], 75))
    tp75 = float(np.percentile([f["tampering_likelihood"] for f in frames], 75))
    flick_score = 0.0 if flicker is None else _clamp((flicker - 0.06) / 0.25)

    reasons: list[str] = [s["description"] for s in strong]
    ai = 0.97 if strong else ai_p75
    tamper = 0.8 * tp75 + 0.2 * flick_score
    if flick_score >= 0.5:
        reasons.append("Sharpness flickers unusually between consecutive frames (typical of face-swap blending).")
    if ai_p75 >= 0.5 and not strong:
        reasons.append("Many sampled frames show generative-image spectral artifacts.")
    if tp75 >= 0.5:
        reasons.append("Many sampled frames show splice/clone inconsistencies.")
    if c2pa:
        reasons.append("Content Credentials (C2PA) data present - verify with an official C2PA validator.")
    overall = max(ai, tamper)
    ranked = sorted(frames, key=lambda f: max(f["ai_likelihood"], f["tampering_likelihood"]), reverse=True)
    return {
        "verdict": ("likely_ai_or_manipulated" if overall >= 0.65
                    else "possibly_manipulated" if overall >= 0.35 else "no_strong_indicators"),
        "overall_score": round(overall, 3),
        "ai_generated_likelihood": round(ai, 3),
        "tampering_likelihood": round(tamper, 3),
        "confidence": "high" if strong else "low",
        "reasons": reasons or ["No strong manipulation indicators were found in the sampled frames."],
        "video": {"duration_s": round(duration, 2), "fps": round(fps, 2), "resolution": [w, h],
                  "frames_analyzed": len(frames), "sharpness_flicker": None if flicker is None else round(flicker, 3)},
        "ai_signatures": sigs,
        "content_credentials_present": c2pa,
        "most_suspicious_frames": [f for f in ranked[:3] if max(f["ai_likelihood"], f["tampering_likelihood"]) >= 0.35],
        "frames": frames,
        "limitations": LIMITATIONS,
    }
