"""Pixel-level forensic heuristics (feature 2: AI-generated & manipulated image screening).

IMPORTANT: these are classical, explainable signals. They give *indications*, not proof.
Each returns a score in [0, 1] plus details. For production-grade AI-generation
detection plug in a trained model (see detector.py).
"""
from __future__ import annotations

import base64
import io
import math
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

from .. import config


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return float(max(lo, min(hi, x)))


def _gray(img: Image.Image, max_side: int = 1024) -> np.ndarray:
    g = np.asarray(img.convert("L"), dtype=np.float32)
    h, w = g.shape
    s = max(h, w)
    if s > max_side:
        g = cv2.resize(g, (int(w * max_side / s), int(h * max_side / s)), interpolation=cv2.INTER_AREA)
    return g


def _block_stat(arr: np.ndarray, bs: int, fn) -> np.ndarray | None:
    h, w = arr.shape
    hb, wb = h // bs, w // bs
    if hb < 4 or wb < 4:
        return None
    return fn(arr[: hb * bs, : wb * bs].reshape(hb, bs, wb, bs))


def error_level_analysis(img: Image.Image, quality: int = 90, want_heatmap: bool = False) -> dict:
    """Re-compress and diff. Regions pasted/edited at a different compression history stand out."""
    small = img
    if max(img.size) > 1600:
        s = 1600 / max(img.size)
        small = img.resize((int(img.width * s), int(img.height * s)), Image.LANCZOS)
    buf = io.BytesIO()
    small.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    re_img = Image.open(buf).convert("RGB")
    diff = np.abs(np.asarray(small, np.int16) - np.asarray(re_img, np.int16)).max(axis=2).astype(np.float32)
    blocks = _block_stat(diff, 16, lambda a: a.mean(axis=(1, 3)))
    out: dict = {"score": 0.0, "detail": "image too small for ELA"}
    if blocks is not None:
        med = float(np.median(blocks))
        mad = float(np.median(np.abs(blocks - med))) * 1.4826 + 1e-3
        hot = blocks > med + 5 * mad
        frac = float(hot.mean())
        # a few big, *connected* hot regions are more suspicious than scattered edge noise
        n_lbl, lbl, stats, _ = cv2.connectedComponentsWithStats(hot.astype(np.uint8), connectivity=8)
        largest = int(stats[1:, cv2.CC_STAT_AREA].max()) if n_lbl > 1 else 0
        score = _clamp((frac - 0.01) / 0.12) * 0.5 + _clamp(largest / 25.0) * 0.5
        out = {"score": round(score, 3), "hot_block_fraction": round(frac, 4),
               "largest_hot_region_blocks": largest,
               "detail": "Uneven compression-error levels across regions (possible edit/splice)."}
    if want_heatmap:
        scaled = np.clip(diff * (255.0 / max(float(diff.max()), 1.0)), 0, 255).astype(np.uint8)
        heat = cv2.applyColorMap(scaled, cv2.COLORMAP_JET)
        ok, png = cv2.imencode(".png", heat)
        if ok:
            out["heatmap_png_b64"] = base64.b64encode(png.tobytes()).decode()
    return out


def noise_inconsistency(gray: np.ndarray) -> dict:
    """Different sources/edits leave different sensor-noise statistics in different regions."""
    resid = gray - cv2.medianBlur(gray.astype(np.uint8), 3).astype(np.float32)
    stds = _block_stat(resid, 32, lambda a: a.std(axis=(1, 3)))
    if stds is None:
        return {"score": 0.0, "detail": "image too small"}
    log = np.log(stds + 1e-2)
    med = float(np.median(log))
    disp = float(np.median(np.abs(log - med))) * 1.4826
    outlier_frac = float((np.abs(log - med) > 3 * (disp + 0.05)).mean())
    score = _clamp((disp - 0.45) / 0.9) * 0.6 + _clamp(outlier_frac / 0.15) * 0.4
    return {"score": round(score, 3), "noise_dispersion": round(disp, 3),
            "outlier_block_fraction": round(outlier_frac, 4),
            "detail": "Noise level differs between regions (weak splice/composite indicator)."}


def spectral_artifacts(gray: np.ndarray) -> dict:
    """Up-sampling layers in GANs/diffusion decoders often leave periodic peaks in the
    high-frequency spectrum of the noise residual."""
    h, w = gray.shape
    n = min(h, w, 512)
    if n < 128:
        return {"score": 0.0, "detail": "image too small for spectral analysis"}
    y0, x0 = (h - n) // 2, (w - n) // 2
    crop = gray[y0:y0 + n, x0:x0 + n]
    resid = crop - cv2.GaussianBlur(crop, (0, 0), 1.0)
    win = np.outer(np.hanning(n), np.hanning(n)).astype(np.float32)
    P = np.log1p(np.abs(np.fft.fftshift(np.fft.fft2(resid * win))))
    yy, xx = np.indices(P.shape)
    r = np.hypot(yy - n // 2, xx - n // 2).astype(np.int32)
    prof = np.bincount(r.ravel(), P.ravel()) / np.maximum(np.bincount(r.ravel()), 1)
    flat = P - prof[r]
    mask = (r > 0.2 * n) & (r < n // 2)
    vals = flat[mask]
    sd = float(vals.std()) + 1e-6
    peak_frac = float((vals > 4.5 * sd).mean())
    top = float(np.sort(vals)[-5:].mean() / sd)
    score = _clamp(peak_frac / 0.004) * 0.5 + _clamp((top - 6.0) / 6.0) * 0.5
    return {"score": round(score, 3), "peak_fraction": round(peak_frac, 5), "top_peak_sigma": round(top, 2),
            "detail": "Periodic high-frequency peaks typical of generative up-sampling."}


def copy_move(gray: np.ndarray) -> dict:
    """Detect regions cloned inside the same image (object removal / duplication)."""
    g8 = np.clip(gray, 0, 255).astype(np.uint8)
    orb = cv2.ORB_create(nfeatures=2500)
    kps, des = orb.detectAndCompute(g8, None)
    if des is None or len(kps) < 30:
        return {"score": 0.0, "matches": 0, "detail": "not enough texture"}
    knn = cv2.BFMatcher(cv2.NORM_HAMMING).knnMatch(des, des, k=4)
    vecs = []
    for m in knn:
        c = [x for x in m if x.trainIdx != x.queryIdx]
        if len(c) < 2 or not (c[0].distance < 0.6 * c[1].distance and c[0].distance < 40):
            continue
        p1, p2 = np.array(kps[c[0].queryIdx].pt), np.array(kps[c[0].trainIdx].pt)
        if math.hypot(*(p2 - p1)) < 40:
            continue
        v = p2 - p1
        if v[0] < 0 or (v[0] == 0 and v[1] < 0):
            v = -v
        vecs.append(v)
    if not vecs:
        return {"score": 0.0, "matches": 0, "detail": "no cloned regions found"}
    bins: dict[tuple[int, int], int] = {}
    for v in vecs:
        key = (int(round(v[0] / 12)), int(round(v[1] / 12)))
        bins[key] = bins.get(key, 0) + 1
    biggest = max(bins.values())
    return {"score": round(_clamp((biggest - 5) / 20.0), 3), "matches": len(vecs),
            "consistent_matches": biggest,
            "detail": "Several keypoints repeat at the same offset (possible cloned region)."}


_cascade = None


def detect_faces(img: Image.Image) -> list[dict] | None:
    """Returns list of face boxes, or None when no face detector is available."""
    global _cascade
    if _cascade is None:
        cands = [config.FACE_CASCADE_PATH, getattr(getattr(cv2, "data", None), "haarcascades", "") + "haarcascade_frontalface_default.xml"]
        for p in cands:
            if p and Path(p).is_file():
                c = cv2.CascadeClassifier(p)
                if not c.empty():
                    _cascade = c
                    break
        if _cascade is None:
            _cascade = False
    if _cascade is False:
        return None
    g = np.asarray(img.convert("L"))
    s = min(1.0, 800 / max(g.shape))
    if s < 1.0:
        g = cv2.resize(g, None, fx=s, fy=s, interpolation=cv2.INTER_AREA)
    faces = _cascade.detectMultiScale(g, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
    return [{"x": int(x / s), "y": int(y / s), "w": int(w / s), "h": int(h / s)} for x, y, w, h in faces]


def run_all(img: Image.Image, jpeg_like: bool, want_heatmap: bool = False) -> dict:
    gray = _gray(img)
    res = {
        "ela": error_level_analysis(img, want_heatmap=want_heatmap),
        "noise": noise_inconsistency(gray),
        "spectral": spectral_artifacts(gray),
        "copy_move": copy_move(gray),
    }
    if not jpeg_like:
        # ELA is much less meaningful for lossless sources (PNG screenshots, AI renders).
        res["ela"]["score"] = round(res["ela"]["score"] * 0.5, 3)
        res["ela"]["note"] = "down-weighted: source is not JPEG"
    return res
