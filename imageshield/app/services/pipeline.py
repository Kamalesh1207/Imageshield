"""Owner-aware orchestration: analysis + registry matching + alert persistence."""
from __future__ import annotations

from datetime import datetime, timezone

from .. import db
from .. import config
from . import detector, registry, watermark
from .imaging import load_image


def save_alerts(owner: str, alerts: list[dict]) -> None:
    if not alerts:
        return
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db.tx() as c:
        c.executemany(
            "INSERT INTO alerts(owner,level,code,title,message,action,created) VALUES(?,?,?,?,?,?,?)",
            [(owner, a["level"], a["code"], a["title"], a["message"], a["action"], now) for a in alerts])


def full_analysis(owner: str, data: bytes, include_heatmap: bool = False) -> dict:
    result = detector.analyze_image(data, include_heatmap)
    hits = registry.find_matches(owner, result["fingerprints"])
    result["registry_matches"] = hits
    if hits:
        suspicious = result["overall_score"] >= 0.35 or not hits[0]["identical_file"]
        if suspicious:
            result["privacy_alerts"].insert(0, {
                "level": "critical" if result["overall_score"] >= 0.65 else "high",
                "code": "misuse_suspected",
                "title": "This looks like one of YOUR registered photos" + (
                    ", and it appears altered" if result["overall_score"] >= 0.35 else ""),
                "message": f"Matched '{hits[0]['label'] or hits[0]['registered_id']}' ({hits[0]['match_type']}).",
                "action": "Open an evidence case, preserve this copy and follow the reporting guide."})
    result["watermark"] = describe_watermark(owner, watermark.detect(load_image(data)[0], config.WM_KEY, full_search=False))
    wm = result["watermark"]
    if wm["found"] and wm["registered_to_you"] and result["overall_score"] >= 0.35:
        result["privacy_alerts"].insert(0, {
            "level": "critical" if result["overall_score"] >= 0.65 else "high", "code": "watermark_misuse",
            "title": "Your invisible watermark was found in an image that looks altered",
            "message": f"Watermark of '{wm['label'] or wm['wm_id']}' detected (agreement {wm['agreement']}).",
            "action": "This copy derives from your published photo. Preserve it and follow the reporting guide."})
    save_alerts(owner, [a for a in result["privacy_alerts"] if a["level"] in ("critical", "high")])
    return result


def describe_watermark(owner: str, det: dict) -> dict:
    """Scope what we reveal: details only for the watermark's owner."""
    if not det.get("found"):
        return {"found": False}
    rec = registry.lookup_watermark(det["wm_id"])
    mine = bool(rec and rec["owner"] == owner)
    return {"found": True, "agreement": det["agreement"], "registered_to_you": mine,
            "wm_id": det["wm_id"] if mine else None, "label": rec["label"] if mine else None,
            "note": None if mine else ("Carries an ImageShield watermark that is not registered to your account."
                                       if rec else "Watermark pattern found but its ID is unknown (possibly a false positive).")}
