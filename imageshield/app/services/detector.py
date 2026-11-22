"""Fuses metadata signatures, forensic heuristics and (optionally) an ML classifier into
one explainable verdict. Pure function of the uploaded bytes - no database access."""
from __future__ import annotations

import logging
import re

from PIL import Image

from .. import config
from . import forensics, hashing, metadata
from .alerts import privacy_alerts
from .imaging import load_image

log = logging.getLogger("imageshield.detector")

LIMITATIONS = [
    "Automated screening gives indications, not proof. A clean result does not mean an image is authentic.",
    "Social platforms strip metadata and re-compress images, which weakens every signal.",
    "Newer generators evade classical forensics; plug in a trained model for better accuracy (IMAGESHIELD_HF_MODEL).",
    "For legal use, have findings confirmed by a qualified forensic examiner.",
]

_pipe = None  # lazily created transformers pipeline; False = unavailable


def _model_score(img: Image.Image) -> float | None:
    """Probability (0-1) that the image is AI-generated according to an optional HF model."""
    global _pipe
    if not config.HF_MODEL_ID or _pipe is False:
        return None
    try:
        if _pipe is None:
            from transformers import pipeline  # optional dependency

            _pipe = pipeline("image-classification", model=config.HF_MODEL_ID)
        out = _pipe(img, top_k=None)
        pos = [o["score"] for o in out
               if re.search(r"\b(ai|fake|artificial|generated|synthetic|deepfake)\b", o["label"], re.I)
               and not re.search(r"\b(real|human|authentic|natural|not)\b", o["label"], re.I)]
        return float(max(pos)) if pos else None
    except Exception:  # never let an optional model break the pipeline
        log.exception("ML detector unavailable; falling back to heuristics")
        _pipe = False
        return None


def fuse(meta: dict, f: dict, model: float | None) -> dict:
    reasons: list[str] = []
    strong = [s for s in meta["ai_signatures"] if s["strength"] == "strong"]
    spectral = f["spectral"]["score"]

    if strong:
        ai, confidence = 0.97, "high"
        reasons += [s["description"] for s in strong]
    elif model is not None:
        ai, confidence = 0.7 * model + 0.3 * spectral, "medium"
        if model >= 0.6:
            reasons.append(f"ML classifier rates the image {model:.0%} likely to be AI-generated.")
    else:
        ai, confidence = min(0.55, 0.6 * spectral), "low"  # heuristics alone never claim certainty
        if spectral >= 0.5:
            reasons.append(f["spectral"]["detail"])

    ela, noise, cm = f["ela"]["score"], f["noise"]["score"], f["copy_move"]["score"]
    tamper = 0.35 * ela + 0.25 * noise + 0.40 * cm
    if cm >= 0.8:
        tamper = max(tamper, 0.75)
    if "edited_with_photo_editor" in meta["flags"]:
        tamper = max(tamper, 0.4)
        reasons.append(f"Metadata shows editing software: {meta['software']}.")
    if "modified_after_capture" in meta["flags"]:
        reasons.append("File was modified after the original capture time.")
    if ela >= 0.5:
        reasons.append(f["ela"]["detail"])
    if noise >= 0.5:
        reasons.append(f["noise"]["detail"])
    if cm >= 0.5:
        reasons.append(f["copy_move"]["detail"])
    if meta["content_credentials_present"]:
        reasons.append("Content Credentials (C2PA) manifest present - verify it with an official C2PA validator.")

    overall = max(ai, tamper)
    verdict = ("likely_ai_or_manipulated" if overall >= 0.65
               else "possibly_manipulated" if overall >= 0.35 else "no_strong_indicators")
    hints = []
    if ai >= 0.5:
        hints.append("ai_generated")
    if cm >= 0.5:
        hints.append("clone_or_object_removal")
    if ela >= 0.5 or noise >= 0.5:
        hints.append("splice_or_composite")
    return {
        "verdict": verdict,
        "overall_score": round(overall, 3),
        "ai_generated_likelihood": round(ai, 3),
        "tampering_likelihood": round(tamper, 3),
        "confidence": confidence,
        "manipulation_hints": hints,
        "reasons": reasons or ["No strong manipulation indicators were found."],
    }


def analyze_image(data: bytes, include_heatmap: bool = False) -> dict:
    img, fmt = load_image(data)
    meta = metadata.extract_metadata(data)
    jpeg_like = fmt == "JPEG"
    f = forensics.run_all(img, jpeg_like, want_heatmap=include_heatmap)
    model = _model_score(img)
    faces = forensics.detect_faces(img)
    verdict = fuse(meta, f, model)
    heat = f["ela"].pop("heatmap_png_b64", None)
    result = {
        **verdict,
        "metadata": meta,
        "forensics": f,
        "ml_model_score": None if model is None else round(model, 3),
        "faces_detected": None if faces is None else len(faces),
        "fingerprints": hashing.fingerprints(img, data),
        "privacy_alerts": privacy_alerts(meta, faces),
        "limitations": LIMITATIONS,
    }
    if heat:
        result["ela_heatmap_png_b64"] = heat
    return result
