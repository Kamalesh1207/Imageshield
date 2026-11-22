"""Image source & metadata analysis (feature 3) and AI-provenance signatures.

Looks for *declared* provenance: IPTC "trainedAlgorithmicMedia", C2PA content
credentials, Stable-Diffusion/ComfyUI PNG text chunks, generator names in
XMP/EXIF. Absence of these proves nothing (platforms strip metadata), but
presence is the strongest evidence we can get.
"""
from __future__ import annotations

import io
import re

from PIL import ExifTags, Image

# (regex on raw bytes, code, human description, strength)
_RAW_MARKERS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(rb"digitalsourcetype/trainedAlgorithmicMedia", re.I), "iptc_ai_generated",
     "IPTC digital source type says: trained algorithmic media (AI-generated).", "strong"),
    (re.compile(rb"digitalsourcetype/compositeWithTrainedAlgorithmicMedia", re.I), "iptc_ai_composite",
     "IPTC digital source type says: composite with AI-generated media (AI-edited).", "strong"),
    (re.compile(rb"digitalsourcetype/(algorithmicMedia|compositeSynthetic)", re.I), "iptc_synthetic",
     "IPTC digital source type marks the image as synthetic.", "strong"),
    (re.compile(rb"Steps: \d+, Sampler:", re.I), "sd_parameters",
     "Stable-Diffusion style generation parameters found in the file.", "strong"),
    (re.compile(rb'"class_type"\s*:', re.I), "comfyui_workflow",
     "ComfyUI workflow JSON embedded in the file.", "strong"),
    (re.compile(rb"Midjourney", re.I), "midjourney", "Midjourney reference found in metadata.", "strong"),
    (re.compile(rb"DALL[- ]?E", re.I), "dalle", "DALL-E reference found in metadata.", "strong"),
    (re.compile(rb"Adobe Firefly|Generative Fill|GenFill", re.I), "firefly",
     "Adobe generative-AI reference found in metadata.", "strong"),
    (re.compile(rb"Stable Diffusion|SDXL|InvokeAI", re.I), "stable_diffusion",
     "Stable Diffusion reference found in metadata.", "strong"),
    (re.compile(rb"\bImagen\b|Made with Google AI", re.I), "google_ai",
     "Google generative-AI reference found in metadata.", "strong"),
]
_C2PA = re.compile(rb"c2pa|jumb", re.I)
_PNG_AI_KEYS = {"parameters", "prompt", "workflow", "invokeai_metadata", "sd-metadata", "dream"}
_EDITORS = re.compile(r"photoshop|lightroom|gimp|snapseed|facetune|picsart|canva|remini|faceapp", re.I)

_GPS_IFD = 0x8825
_EXIF_IFD = 0x8769


def _safe(v, depth: int = 0):
    """Make EXIF values JSON friendly."""
    if isinstance(v, bytes):
        return v[:80].decode("utf-8", "replace")
    if isinstance(v, (tuple, list)) and depth < 3:
        return [_safe(x, depth + 1) for x in v][:16]
    if isinstance(v, dict) and depth < 3:
        return {str(k): _safe(x, depth + 1) for k, x in list(v.items())[:32]}
    if isinstance(v, (int, str, bool)) or v is None:
        return v[:200] if isinstance(v, str) else v
    try:
        return float(v)
    except Exception:
        return str(v)[:200]


def _dms_to_deg(dms, ref) -> float | None:
    try:
        d, m, s = (float(x) for x in dms)
        deg = d + m / 60 + s / 3600
        return -deg if str(ref).upper() in ("S", "W") else deg
    except Exception:
        return None


def scan_signatures(data: bytes) -> tuple[list[dict], bool]:
    """Scan raw bytes (head + tail) for AI-provenance strings. Works for images and video containers.
    Returns (signatures, c2pa_present)."""
    blob = data[: 1024 * 1024] + data[-65536:]
    sigs: list[dict] = []
    seen: set[str] = set()
    for pat, code, desc, strength in _RAW_MARKERS:
        if pat.search(blob) and code not in seen:
            seen.add(code)
            sigs.append({"code": code, "description": desc, "strength": strength})
    return sigs, bool(_C2PA.search(blob)) and b"c2pa" in blob.lower()


def extract_metadata(data: bytes) -> dict:
    img = Image.open(io.BytesIO(data))
    fmt = img.format
    exif = img.getexif()
    tags: dict = {}
    for tag, val in exif.items():
        tags[ExifTags.TAGS.get(tag, str(tag))] = _safe(val)
    try:
        for tag, val in exif.get_ifd(_EXIF_IFD).items():
            tags[ExifTags.TAGS.get(tag, str(tag))] = _safe(val)
    except Exception:
        pass
    gps_raw = {}
    try:
        gps_raw = dict(exif.get_ifd(_GPS_IFD))
    except Exception:
        pass

    gps_approx = None
    if gps_raw:
        lat = _dms_to_deg(gps_raw.get(2), gps_raw.get(1)) if gps_raw.get(2) else None
        lon = _dms_to_deg(gps_raw.get(4), gps_raw.get(3)) if gps_raw.get(4) else None
        if lat is not None and lon is not None:
            # Rounded to ~1 km on purpose: we never echo exact coordinates back.
            gps_approx = {"lat": round(lat, 2), "lon": round(lon, 2)}

    signatures, c2pa = scan_signatures(data)
    seen = {x["code"] for x in signatures}

    png_text = {}
    if fmt == "PNG":
        for k, v in img.info.items():
            if isinstance(v, (str, bytes)):
                png_text[str(k)] = v
        hit = [k for k in png_text if k.lower() in _PNG_AI_KEYS]
        if hit and "png_ai_chunk" not in seen:
            signatures.append({"code": "png_ai_chunk", "strength": "strong",
                               "description": f"PNG text chunk(s) typical of AI tools: {', '.join(hit)}."})

    software = str(tags.get("Software", "") or "")
    editor_hit = bool(_EDITORS.search(software))
    thumbnail = fmt == "JPEG" and data[: 128 * 1024].count(b"\xff\xd8\xff") >= 2

    flags: list[str] = []
    if not tags and not png_text:
        flags.append("no_metadata")  # normal after social-media upload; weak signal only
    if editor_hit:
        flags.append("edited_with_photo_editor")
    dt_o, dt_m = tags.get("DateTimeOriginal"), tags.get("DateTime")
    if dt_o and dt_m and dt_o != dt_m:
        flags.append("modified_after_capture")
    if tags and not tags.get("Make") and not tags.get("Model"):
        flags.append("no_camera_info")

    return {
        "format": fmt,
        "width": img.size[0],
        "height": img.size[1],
        "has_exif": bool(tags),
        "camera": " ".join(x for x in (str(tags.get("Make", "")).strip(), str(tags.get("Model", "")).strip()) if x) or None,
        "software": software or None,
        "datetime_original": dt_o,
        "datetime_modified": dt_m,
        "serial_numbers_present": any("Serial" in k for k in tags),
        "gps_present": bool(gps_raw),
        "gps_approx": gps_approx,
        "embedded_thumbnail": thumbnail,
        "owner_fields": {k: tags[k] for k in ("Artist", "Copyright", "CameraOwnerName") if tags.get(k)},
        "content_credentials_present": c2pa,
        "ai_signatures": signatures,
        "flags": flags,
    }
