"""Safe evidence organisation (feature 5).

* Files are encrypted at rest (Fernet) and never stored under user-supplied names.
* Every entry is linked into a per-case SHA-256 hash chain (tamper-evident log).
* Export produces a ZIP: manifest, chain of custody, originals, analysis reports.

A hash chain proves the file has not changed *since upload*. It cannot prove the file was
authentic before upload - tell users to also capture the page URL, date/time and a screenshot of the
platform page, and to consult a lawyer about admissibility rules in their country.
"""
from __future__ import annotations

import io
import json
import os
import uuid
import zipfile
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken

from .. import config, db
from . import hashing

GENESIS = "0" * 64
_EXT = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}


class EvidenceError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _fernet() -> Fernet:
    key = os.getenv("IMAGESHIELD_VAULT_KEY")
    keyfile = config.DATA_DIR / "vault.key"
    if not key:
        if keyfile.exists():
            key = keyfile.read_text().strip()
        else:  # dev convenience only - in production inject the key from a secret manager / KMS
            key = Fernet.generate_key().decode()
            keyfile.write_text(key)
            os.chmod(keyfile, 0o600)
    return Fernet(key.encode())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _entry_hash(p: dict) -> str:
    return hashing.sha256_hex(json.dumps(p, sort_keys=True, separators=(",", ":")).encode())


def _payload(row: dict) -> dict:
    return {k: row[k] for k in ("seq", "case_id", "sha256", "kind", "source_url", "platform",
                                "note", "captured_at", "analysis_sha256", "prev_hash")}


# ---------------------------------------------------------------- cases
def create_case(owner: str, title: str, platform: str | None, content_type: str | None, is_minor: bool) -> dict:
    cid = uuid.uuid4().hex
    with db.tx() as c:
        c.execute("INSERT INTO cases(id,owner,title,platform,content_type,is_minor,created) VALUES(?,?,?,?,?,?,?)",
                  (cid, owner, title, platform, content_type, int(is_minor), _now()))
    return get_case(owner, cid)


def get_case(owner: str, case_id: str) -> dict:
    rows = db.query("SELECT * FROM cases WHERE id=? AND owner=?", (case_id, owner))
    if not rows:  # same answer for "missing" and "not yours" - no existence leak
        raise EvidenceError("Case not found.", 404)
    return dict(rows[0])


def list_cases(owner: str) -> list[dict]:
    return [dict(r) for r in db.query("SELECT * FROM cases WHERE owner=? ORDER BY created DESC", (owner,))]


# ---------------------------------------------------------------- evidence
def add_evidence(owner: str, case_id: str, data: bytes | None, *, mime: str | None = None, kind: str = "screenshot",
                 source_url: str | None = None, platform: str | None = None, note: str | None = None,
                 analysis: dict | None = None, store_file: bool = True) -> dict:
    """store_file=False records only the metadata (URL, time, note). Use it for sexual images of
    minors: keeping or copying such files can itself be illegal - report them, don't archive them."""
    case = get_case(owner, case_id)
    if case["is_minor"] and data is not None and kind in ("intimate_image", "screenshot_sensitive"):
        store_file = False
    stored_name = None
    sha = None
    size = 0
    if store_file and data is not None:
        sha = hashing.sha256_hex(data)
        size = len(data)
        stored_name = uuid.uuid4().hex + ".enc"  # never derived from user input
        d = config.VAULT_DIR / owner / case_id
        d.mkdir(parents=True, exist_ok=True)
        (d / stored_name).write_bytes(_fernet().encrypt(data))
    analysis_json = json.dumps(analysis, sort_keys=True, default=str) if analysis else None
    analysis_sha = hashing.sha256_hex(analysis_json.encode()) if analysis_json else None

    with db.tx() as c:
        last = c.execute("SELECT seq, entry_hash FROM evidence WHERE case_id=? ORDER BY seq DESC LIMIT 1",
                         (case_id,)).fetchone()
        row = {"id": uuid.uuid4().hex, "case_id": case_id, "owner": owner,
               "seq": (last["seq"] + 1) if last else 1, "kind": kind, "mime": mime, "size": size,
               "sha256": sha, "stored_name": stored_name, "source_url": source_url, "platform": platform,
               "note": note, "captured_at": _now(), "analysis_json": analysis_json,
               "analysis_sha256": analysis_sha, "prev_hash": last["entry_hash"] if last else GENESIS}
        row["entry_hash"] = _entry_hash(_payload(row))
        cols = ",".join(row)
        c.execute(f"INSERT INTO evidence({cols}) VALUES({','.join('?' * len(row))})", tuple(row.values()))
    return _public(row)


def _public(r: dict) -> dict:
    return {k: r[k] for k in ("id", "case_id", "seq", "kind", "mime", "size", "sha256", "source_url",
                              "platform", "note", "captured_at", "prev_hash", "entry_hash")} | {
        "file_stored": bool(r["stored_name"])}


def list_evidence(owner: str, case_id: str) -> list[dict]:
    get_case(owner, case_id)
    return [_public(dict(r)) for r in db.query("SELECT * FROM evidence WHERE case_id=? ORDER BY seq", (case_id,))]


def _read_file(owner: str, case_id: str, stored_name: str) -> bytes:
    return _fernet().decrypt((config.VAULT_DIR / owner / case_id / stored_name).read_bytes())


def verify_chain(owner: str, case_id: str) -> dict:
    get_case(owner, case_id)
    rows = [dict(r) for r in db.query("SELECT * FROM evidence WHERE case_id=? ORDER BY seq", (case_id,))]
    issues: list[str] = []
    prev = GENESIS
    for i, r in enumerate(rows, 1):
        if r["seq"] != i:
            issues.append(f"#{r['seq']}: sequence gap (entry deleted?)")
        if r["prev_hash"] != prev:
            issues.append(f"#{r['seq']}: chain link broken")
        if _entry_hash(_payload(r)) != r["entry_hash"]:
            issues.append(f"#{r['seq']}: entry record was altered")
        if r["analysis_json"] and hashing.sha256_hex(r["analysis_json"].encode()) != r["analysis_sha256"]:
            issues.append(f"#{r['seq']}: analysis report was altered")
        if r["stored_name"]:
            try:
                if hashing.sha256_hex(_read_file(owner, case_id, r["stored_name"])) != r["sha256"]:
                    issues.append(f"#{r['seq']}: file content does not match recorded hash")
            except (FileNotFoundError, InvalidToken):
                issues.append(f"#{r['seq']}: stored file missing or corrupted")
        prev = r["entry_hash"]
    return {"ok": not issues, "entries": len(rows), "head_hash": prev, "issues": issues}


def export_zip(owner: str, case_id: str) -> bytes:
    case = get_case(owner, case_id)
    rows = [dict(r) for r in db.query("SELECT * FROM evidence WHERE case_id=? ORDER BY seq", (case_id,))]
    check = verify_chain(owner, case_id)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = {"exported_at": _now(), "case": {k: case[k] for k in ("id", "title", "platform", "content_type", "created")},
                    "integrity_check": check, "entries": [_public(r) for r in rows]}
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
        lines = [f"CHAIN OF CUSTODY - case {case_id}", f"Exported: {manifest['exported_at']}",
                 f"Integrity check: {'PASSED' if check['ok'] else 'FAILED'}", f"Head hash: {check['head_hash']}", ""]
        for r in rows:
            lines += [f"#{r['seq']}  {r['captured_at']}  kind={r['kind']}  platform={r['platform'] or '-'}",
                      f"    source: {r['source_url'] or '-'}", f"    sha256: {r['sha256'] or '(file not stored)'}",
                      f"    note: {r['note'] or '-'}", f"    entry_hash: {r['entry_hash']}", ""]
            if r["stored_name"]:
                ext = _EXT.get(r["mime"] or "", ".bin")
                z.writestr(f"files/{r['seq']:03d}_{r['sha256'][:8]}{ext}", _read_file(owner, case_id, r["stored_name"]))
            if r["analysis_json"]:
                z.writestr(f"analysis/{r['seq']:03d}.json", r["analysis_json"])
        z.writestr("chain_of_custody.txt", "\n".join(lines))
        z.writestr("README.txt", (
            "How to verify: recompute SHA-256 of each file in /files and compare with manifest.json.\n"
            "Each entry_hash covers the entry fields plus the previous entry_hash (tamper-evident chain).\n"
            "Automated image analysis is indicative, not conclusive.\n"
            "Courts may require extra formalities for electronic evidence (e.g. a certificate under Section 63 of the\n"
            "Bharatiya Sakshya Adhiniyam in India). Confirm requirements with a lawyer.\n"))
    return buf.getvalue()
