"""Invisible watermarking: embed a hidden, keyed 48-bit ID into a photo before you publish it.

If a copy later turns up (even recompressed, partly pasted-over or cropped) the ID can be recovered
and traced back to the registered original -> proof that the image derives from your photo,
even after a face-swap that only touches part of the frame.

How it works (frequency-domain, "relation" watermark):
  * Work on luminance (Y). Split into 8x8 blocks, take the DCT of each.
  * Each block carries ONE bit in the sign of  c(2,3) - c(3,2)  (pushed to +/-delta).
  * The 64 payload bits (48-bit ID + CRC-16) are laid out on an 8x8 *tile* of blocks in a
    secret keyed order and repeated over the whole image -> hundreds of votes per bit.
  * Detection sums soft votes per tile cell, searches the 64 pixel offsets + 64 tile phases so
    cropped images still decode, checks CRC and reports an agreement score.

Honest limits: survives JPEG re-compression (about q>=60), mild noise, partial edits and
crops. It does NOT survive heavy resizing/rotation, screenshots at another scale, or a determined
attacker who knows the method. Treat it as supporting evidence, not proof.
"""
from __future__ import annotations

import binascii
import hashlib
import secrets

import numpy as np
from PIL import Image
from scipy.fft import dctn, idctn

BLOCK = 8
PAYLOAD_BITS = 64
MIN_SIDE = 128
AGREEMENT_THRESHOLD = 0.25
_A, _B = (2, 3), (3, 2)


class WatermarkError(ValueError):
    pass


def new_id() -> str:
    return secrets.token_bytes(6).hex()


def _bits(wm_id: str) -> np.ndarray:
    raw = bytes.fromhex(wm_id)
    if len(raw) != 6:
        raise WatermarkError("Watermark id must be 6 bytes (12 hex chars).")
    raw += binascii.crc_hqx(raw, 0).to_bytes(2, "big")
    return np.unpackbits(np.frombuffer(raw, np.uint8)).astype(np.int8)


def _decode(bits: np.ndarray) -> str | None:
    raw = np.packbits(bits.astype(np.uint8)).tobytes()
    return raw[:6].hex() if binascii.crc_hqx(raw[:6], 0) == int.from_bytes(raw[6:], "big") else None


def _perm(key: bytes) -> np.ndarray:
    seed = int.from_bytes(hashlib.sha256(key + b"|perm").digest()[:8], "big")
    return np.random.default_rng(seed).permutation(PAYLOAD_BITS)


def _blocks(Y: np.ndarray) -> np.ndarray:
    hb, wb = Y.shape[0] // BLOCK, Y.shape[1] // BLOCK
    return Y[: hb * BLOCK, : wb * BLOCK].reshape(hb, BLOCK, wb, BLOCK).transpose(0, 2, 1, 3)


def _tile_index(hb: int, wb: int) -> np.ndarray:
    rr, cc = np.indices((hb, wb))
    return (rr % 8) * 8 + (cc % 8)


def embed(img: Image.Image, wm_id: str, key: bytes, delta: float = 20.0) -> Image.Image:
    rgb = img.convert("RGB")
    if min(rgb.size) < MIN_SIDE:
        raise WatermarkError(f"Image too small (minimum {MIN_SIDE}px on each side).")
    y, cb, cr = rgb.convert("YCbCr").split()
    Y = np.asarray(y, dtype=np.float64)
    blocks = _blocks(Y)
    hb, wb = blocks.shape[:2]
    D = dctn(blocks, axes=(2, 3), norm="ortho")

    bit = _bits(wm_id)[_perm(key)[_tile_index(hb, wb)]]
    sign = np.where(bit == 1, 1.0, -1.0)
    d = D[:, :, _A[0], _A[1]] - D[:, :, _B[0], _B[1]]
    shift = sign * np.maximum(0.0, delta - sign * d) / 2.0   # only push blocks that don't already comply
    D[:, :, _A[0], _A[1]] += shift
    D[:, :, _B[0], _B[1]] -= shift

    out = idctn(D, axes=(2, 3), norm="ortho").transpose(0, 2, 1, 3).reshape(hb * BLOCK, wb * BLOCK)
    Y2 = Y.copy()
    Y2[: hb * BLOCK, : wb * BLOCK] = out
    y2 = Image.fromarray(np.clip(np.rint(Y2), 0, 255).astype(np.uint8))
    return Image.merge("YCbCr", (y2, cb, cr)).convert("RGB")


def detect(img: Image.Image, key: bytes, delta: float = 20.0, full_search: bool = True) -> dict:
    """full_search=False only tries the original pixel grid (fast; fine for uncropped images)."""
    rgb = img.convert("RGB")
    if min(rgb.size) < MIN_SIDE:
        return {"found": False, "reason": "image too small"}
    Y = np.asarray(rgb.convert("YCbCr").split()[0], dtype=np.float64)
    H, W = Y.shape
    ch, cw = min(H, 1536) // 8 * 8, min(W, 1536) // 8 * 8          # bounded work on huge images
    y0, x0 = ((H - ch) // 2) // 8 * 8, ((W - cw) // 2) // 8 * 8      # keep the original 8px grid
    Y = Y[y0:y0 + ch, x0:x0 + cw]
    perm = _perm(key)
    offsets = [(oy, ox) for oy in range(8) for ox in range(8)] if full_search else [(0, 0)]

    best = {"found": False, "agreement": 0.0, "wm_id": None}
    for oy, ox in offsets:
        sub = Y[oy:, ox:]
        if min(sub.shape) < 64:
            continue
        D = dctn(_blocks(sub), axes=(2, 3), norm="ortho")
        soft = np.clip((D[:, :, _A[0], _A[1]] - D[:, :, _B[0], _B[1]]) / delta, -1, 1)
        q = _tile_index(*soft.shape).ravel()
        S = np.bincount(q, soft.ravel(), minlength=64).reshape(8, 8)
        N = np.maximum(np.bincount(q, minlength=64).reshape(8, 8), 1)
        for dr in range(8):
            for dc in range(8):
                M = (np.roll(S, (dr, dc), (0, 1)) / np.roll(N, (dr, dc), (0, 1))).ravel()
                M = M - M.mean()                                  # remove natural-image bias
                vals = np.empty(PAYLOAD_BITS)
                vals[perm] = M                                    # value per payload bit
                wm_id = _decode((vals > 0).astype(np.int8))
                agreement = float(np.abs(vals).mean())
                if wm_id and agreement > best["agreement"]:
                    best = {"found": agreement >= AGREEMENT_THRESHOLD, "agreement": agreement, "wm_id": wm_id,
                            "grid_offset": [oy, ox], "tile_phase": [dr, dc]}
    best["agreement"] = round(best["agreement"], 3)
    if not best["found"]:
        best["wm_id"] = None
    return best
