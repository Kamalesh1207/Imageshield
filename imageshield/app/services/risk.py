"""Personal image-misuse risk assessment (feature 1). Transparent, rule-based scoring so users
(and hackathon judges) can see exactly *why* a score was given."""
from __future__ import annotations

from ..schemas import RiskQuestionnaire

# (field, points, factor text, recommendation)
_RULES = [
    ("is_minor", 20, "User is under 18 - higher exposure to coercion and image-based abuse.",
     "Talk to a trusted adult. If anyone pressures you for images, stop replying, keep the messages and report."),
    ("profile_public", 15, "Profile is public, so anyone can download your photos.",
     "Switch to a private account / limit audience for photos with your face."),
    ("posts_face_photos", 12, "Clear face photos are posted online (raw material for face-swap deepfakes).",
     "Post fewer high-resolution front-facing close-ups; keep the best originals private."),
    ("unknown_followers", 10, "Followers or contacts you don't know personally can see your photos.",
     "Remove unknown followers and review who can see your stories and tags."),
    ("shares_location", 8, "Photos or posts reveal where you are or live.",
     "Turn off location tags and strip metadata before posting."),
    ("previously_harassed", 12, "You've been harassed online before.",
     "Enable alerts, tighten privacy settings and document any new incident right away."),
    ("conflict_with_person_holding_images", 18, "Someone who holds your private images is in conflict with you.",
     "Consider StopNCII-style hashing of those images now, before anything is posted."),
    ("public_figure_or_creator", 10, "Public visibility makes you a bigger target for impersonation.",
     "Register your originals in the protected registry and watermark public posts."),
    ("has_found_edited_copy", 25, "You've already found an edited or fake copy of your photo.",
     "Open an evidence case immediately and follow the reporting guide."),
]


def _level(score: int) -> str:
    return "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"


def assess(q: RiskQuestionnaire, analysis: dict | None = None, registry_hits: list | None = None) -> dict:
    factors, recs, score = [], [], 0
    for field, pts, text, rec in _RULES:
        if getattr(q, field):
            score += pts
            factors.append({"factor": text, "points": pts})
            recs.append(rec)
    if q.public_photo_count > 50:
        score += 8
        factors.append({"factor": "Large public photo library (50+ images).", "points": 8})
        recs.append("Archive or hide old photos you no longer need public.")
    if analysis:
        if analysis.get("overall_score", 0) >= 0.65:
            score += 15
            factors.append({"factor": "The analysed image shows strong signs of AI generation or manipulation.", "points": 15})
        if analysis["metadata"]["gps_present"]:
            score += 8
            factors.append({"factor": "The analysed image leaks GPS location.", "points": 8})
            recs.append("Always scrub metadata before posting.")
    if registry_hits:
        score += 20
        factors.append({"factor": "A copy/derivative of your registered photo was found.", "points": 20})
        recs.append("Preserve the evidence and report the copy.")
    score = min(100, score)
    return {"score": score, "level": _level(score), "factors": factors,
            "recommendations": list(dict.fromkeys(recs)),
            "note": "Rule-based self-assessment to guide next steps; not a prediction that anything will happen."}
