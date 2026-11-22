"""Safe image loading: size/pixel limits, format allow-list, EXIF orientation."""
from __future__ import annotations

import io

from PIL import Image, ImageOps, UnidentifiedImageError

from .. import config


class ImageError(ValueError):
    """Raised for anything wrong with an uploaded image (maps to HTTP 400/413/415)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def load_image(data: bytes) -> tuple[Image.Image, str]:
    """Return (RGB image with orientation applied, original format)."""
    if not data:
        raise ImageError("Empty file.")
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise ImageError("File too large.", 413)
    try:
        img = Image.open(io.BytesIO(data))
        fmt = (img.format or "").upper()
        if fmt not in config.ALLOWED_FORMATS:
            raise ImageError(f"Unsupported image format '{fmt}'. Use JPEG, PNG or WEBP.", 415)
        w, h = img.size  # lazy: no pixel decoding yet
        if w * h > config.MAX_PIXELS:
            raise ImageError("Image resolution too large.", 413)
        img.load()
    except ImageError:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError, Image.DecompressionBombError) as exc:
        raise ImageError("File is not a valid image.") from exc
    img = ImageOps.exif_transpose(img)
    return img.convert("RGB"), fmt
