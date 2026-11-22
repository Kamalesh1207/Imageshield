"""Protected-photo registry: users register their own photos (hashes only, never the image) so that
re-uploads, crops, filters or AI-edited derivatives found elsewhere can be recognised."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .. import db
from . import hashing


def register(owner: str, label: str | None, fp: dict) -> dict:
    rid = uuid.uuid4().hex
    with db.tx() as c:
        c.execute("INSERT INTO protected_images(id,owner,label,phash,dhash,sha256,created) VALUES(?,?,?,?,?,?,?)",
                  (rid, owner, label, fp["phash"], fp["dhash"], fp["sha256"],
                   datetime.now(timezone.utc).isoformat(timespec="seconds")))
    return {"id": rid, "label": label, "phash": fp["phash"], "dhash": fp["dhash"]}


def list_registered(owner: str) -> list[dict]:
    return [dict(r) for r in db.query(
        "SELECT id,label,phash,dhash,created FROM protected_images WHERE owner=? ORDER BY created DESC", (owner,))]


def find_matches(owner: str, fp: dict) -> list[dict]:
    out = []
    for r in db.query("SELECT id,label,phash,dhash,sha256 FROM protected_images WHERE owner=?", (owner,)):
        m = hashing.classify_match(fp["phash"], fp["dhash"], r["phash"], r["dhash"])
        if m:
            m.update({"registered_id": r["id"], "label": r["label"], "identical_file": r["sha256"] == fp["sha256"]})
            out.append(m)
    return sorted(out, key=lambda x: min(x["phash_distance"], x["dhash_distance"]))


# ------------------------------------------------------------------ invisible-watermark ids
def register_watermark(owner: str, label: str | None, wm_id: str) -> None:
    with db.tx() as c:
        c.execute("INSERT INTO watermarks(wm_id,owner,label,created) VALUES(?,?,?,?)",
                  (wm_id, owner, label, datetime.now(timezone.utc).isoformat(timespec="seconds")))


def lookup_watermark(wm_id: str) -> dict | None:
    rows = db.query("SELECT wm_id,owner,label,created FROM watermarks WHERE wm_id=?", (wm_id,))
    return dict(rows[0]) if rows else None
