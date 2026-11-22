"""Privacy risk alerts (feature 4) and metadata scrubbing before posting."""
from __future__ import annotations

import io

import numpy as np
from PIL import Image, ImageOps


def _a(level: str, code: str, title: str, message: str, action: str) -> dict:
    return {"level": level, "code": code, "title": title, "message": message, "action": action}


def privacy_alerts(meta: dict, faces: list | None) -> list[dict]:
    out: list[dict] = []
    if meta["gps_present"]:
        out.append(_a("high", "gps_location", "Location is embedded in this photo",
                      "Anyone who downloads the original file can see where it was taken.",
                      "Use /v1/privacy/scrub (or turn off camera location tags) before posting."))
    if meta["serial_numbers_present"]:
        out.append(_a("medium", "device_serial", "Device serial number embedded",
                      "Serial numbers can link photos to your device across accounts.",
                      "Strip metadata before sharing."))
    if meta["embedded_thumbnail"]:
        out.append(_a("medium", "embedded_thumbnail", "Embedded thumbnail may reveal the uncropped original",
                      "Cropped photos sometimes still carry the full-frame preview inside.",
                      "Strip metadata before sharing."))
    if meta["owner_fields"]:
        out.append(_a("medium", "owner_name", "Owner/author name stored in metadata",
                      "Your name or copyright text is attached to the file.", "Strip metadata if you want anonymity."))
    if meta["datetime_original"]:
        out.append(_a("low", "capture_time", "Capture date/time embedded",
                      "Reveals when the photo was taken (daily routines, travel dates).",
                      "Strip metadata before sharing."))
    if faces:
        out.append(_a("medium", "face_visible", "A clear face is visible",
                      "Clear, front-facing faces are what face-swap/deepfake tools need most.",
                      "Consider limiting audience, using lower-resolution uploads or a watermark."))
    return out


def scrub_metadata(img: Image.Image, fmt: str) -> tuple[bytes, str]:
    """Re-encode pixels only: drops EXIF/GPS/XMP/text chunks/thumbnails. Returns (bytes, mime)."""
    clean = Image.fromarray(np.asarray(ImageOps.exif_transpose(img).convert("RGB")))
    buf = io.BytesIO()
    if fmt == "PNG":
        clean.save(buf, "PNG", optimize=True)
        return buf.getvalue(), "image/png"
    if fmt == "WEBP":
        clean.save(buf, "WEBP", quality=95)
        return buf.getvalue(), "image/webp"
    clean.save(buf, "JPEG", quality=95, optimize=True)
    return buf.getvalue(), "image/jpeg"
