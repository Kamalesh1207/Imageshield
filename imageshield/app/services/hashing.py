"""Cryptographic + perceptual hashes.

* sha256  – exact-file fingerprint (evidence integrity)
* phash   – DCT perceptual hash, robust to resize / recompression / mild edits
* dhash   – gradient hash, robust to brightness/contrast changes
Perceptual hashes let us find re-uploads or altered copies of a user's *registered*
photo without storing the photo itself (only 64-bit hashes are kept).
"""
from __future__ import annotations

import hashlib

import numpy as np
from PIL import Image
from scipy.fft import dct

from .. import config


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bits_to_hex(bits: np.ndarray) -> str:
    value = 0
    for b in bits.flatten():
        value = (value << 1) | int(b)
    return f"{value:016x}"


def phash(img: Image.Image) -> str:
    g = np.asarray(img.convert("L").resize((32, 32), Image.LANCZOS), dtype=np.float64)
    low = dct(dct(g, axis=0, norm="ortho"), axis=1, norm="ortho")[:8, :8]
    med = np.median(low.flatten()[1:])  # ignore DC term
    return _bits_to_hex(low > med)


def dhash(img: Image.Image) -> str:
    g = np.asarray(img.convert("L").resize((9, 8), Image.LANCZOS), dtype=np.float64)
    return _bits_to_hex(g[:, 1:] > g[:, :-1])


def hamming(a_hex: str, b_hex: str) -> int:
    return bin(int(a_hex, 16) ^ int(b_hex, 16)).count("1")


def fingerprints(img: Image.Image, raw: bytes) -> dict:
    return {"sha256": sha256_hex(raw), "phash": phash(img), "dhash": dhash(img)}


def classify_match(phash_a: str, dhash_a: str, phash_b: str, dhash_b: str) -> dict | None:
    dp, dd = hamming(phash_a, phash_b), hamming(dhash_a, dhash_b)
    best = min(dp, dd)
    if best <= config.MATCH_NEAR_DUPLICATE:
        kind = "near_duplicate"
    elif best <= config.MATCH_DERIVED and max(dp, dd) <= 24:
        kind = "possible_derivative"
    else:
        return None
    return {"match_type": kind, "phash_distance": dp, "dhash_distance": dd}
