"""Step-by-step reporting guidance (feature 6) + complaint draft generator.

The guidance is DATA, not logic - edit the dictionaries below (or load them from JSON/DB) to
add countries and platforms. VERIFY every link/number before release; services change.
"""
from __future__ import annotations

from datetime import datetime, timezone

DISCLAIMER = ("General guidance, not legal advice. Menu names and links change over time - verify before relying "
              "on them. If you are in immediate danger, call your local emergency number.")

PLATFORM_HOWTO = {
    "instagram": "Open the post/profile/message -> tap the ... menu -> Report, then pick the closest reason "
                 "(nudity, harassment, impersonation, false/manipulated content).",
    "facebook": "On the post/profile tap the ... menu -> Find support or report, then pick the closest reason.",
    "whatsapp": "Press and hold the message -> ... -> Report (or open the chat -> contact name -> Report). "
                "Also block the sender.",
    "x": "On the post/profile use the ... menu -> Report; choose abuse/harassment, private media or synthetic/manipulated media.",
    "tiktok": "Press and hold the video (or use Share -> Report) and choose the closest reason.",
    "youtube": "Under the video use ... -> Report; for privacy violations also use the Privacy complaint process.",
    "snapchat": "Press and hold the Snap/profile -> Report Snap/Report.",
    "telegram": "Tap the message -> Report, or email the platform's abuse contact; also report the channel/group.",
    "other": "Look for a Report / Flag / Abuse link on the post, or the site's Trust & Safety / abuse contact form. "
             "If the site is unresponsive, report to its hosting provider (look up the domain with a WHOIS lookup).",
}

COUNTRY = {
    "IN": {"name": "India", "police": [
        {"label": "National Cyber Crime Reporting Portal", "url": "https://cybercrime.gov.in"},
        {"label": "Cyber crime helpline", "phone": "1930"},
        {"label": "Emergency", "phone": "112"}]},
    "US": {"name": "United States", "police": [
        {"label": "FBI Internet Crime Complaint Center (IC3)", "url": "https://www.ic3.gov"},
        {"label": "Local police (non-emergency) / 911 if in danger"}]},
    "GB": {"name": "United Kingdom", "police": [
        {"label": "Police - 101 (non-emergency) / 999 in danger"},
        {"label": "Report Harmful Content", "url": "https://reportharmfulcontent.com"}]},
    "DEFAULT": {"name": "Your country", "police": [
        {"label": "Local police cybercrime unit / national cybercrime reporting portal"}]},
}

ADULT_NCII = {"label": "StopNCII.org - hash-based removal of intimate images (adults); your image never leaves your device",
              "url": "https://stopncii.org"}
MINOR_NCII = {"label": "Take It Down (NCMEC) - hash-based removal for images of under-18s", "url": "https://takeitdown.ncmec.org"}


def guide(platform: str = "other", country: str = "IN", content_type: str = "ai_generated_or_edited",
          is_minor: bool = False) -> dict:
    c = COUNTRY.get(country.upper(), COUNTRY["DEFAULT"])
    steps: list[dict] = []

    def add(title: str, details: str, links: list | None = None):
        steps.append({"step": len(steps) + 1, "title": title, "details": details, "links": links or []})

    add("Stay calm and don't engage",
        "Don't reply to, negotiate with or pay anyone threatening you. Don't delete messages or your own posts yet.")
    if is_minor and content_type == "intimate_or_sexual":
        add("Do NOT save, copy or forward the image",
            "Sexual images of anyone under 18 must not be stored or shared, even as 'evidence'. Record only the link, "
            "username, date/time and what happened (the evidence vault supports 'record only' entries).")
        add("Tell a trusted adult and request removal",
            "Use hash-based removal so the image itself is never uploaded anywhere.", [MINOR_NCII])
    else:
        add("Preserve evidence safely",
            "Capture the full screenshot showing URL, username and date/time; copy the exact link; save the original "
            "file if you have it. Add each item to an ImageShield case so it is hashed and time-stamped.")
    add("Report on the platform", PLATFORM_HOWTO.get(platform, PLATFORM_HOWTO["other"]) +
        " Keep the report reference number/screenshot of your submission.")
    if content_type == "intimate_or_sexual" and not is_minor:
        add("Block re-uploads with hashing", "Create a hash of the image on your own device; participating platforms "
            "then block matching uploads.", [ADULT_NCII])
    if content_type in ("ai_generated_or_edited", "impersonation"):
        add("Say it is fake / impersonation",
            "In the report, state clearly that the image is AI-generated or altered and that you did not consent. "
            "Attach your original photo and the ImageShield analysis summary if the form allows.")
    add("File a police / cybercrime complaint",
        "Share your evidence export (chain-of-custody ZIP) and ask for a complaint/FIR or acknowledgement number.",
        c["police"])
    add("Follow up and escalate",
        "If the platform has not acted within a few days, resubmit through its legal/privacy form, contact the "
        "hosting provider, and consider legal advice (takedown notices, protection orders).")
    add("Look after yourself",
        "This is not your fault. Talk to someone you trust; a counsellor or a local victim-support helpline can help.")
    return {"platform": platform, "country": c["name"], "content_type": content_type, "is_minor": is_minor,
            "steps": steps, "disclaimer": DISCLAIMER}


def draft_complaint(case: dict, evidence: list[dict], country: str = "IN") -> str:
    """Plain-text complaint the user can paste into a portal/email. Contains no analysis claims
    stronger than the evidence supports."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"COMPLAINT SUMMARY (generated {now})", "",
             f"Subject: {case['title']}",
             f"Platform(s): {case.get('platform') or 'see evidence list'}",
             f"Nature: {(case.get('content_type') or 'misuse of my personal image').replace('_', ' ')}", "",
             "I am the person depicted. I did not consent to the creation, alteration or sharing of this content.", "",
             "Evidence (each item hashed with SHA-256 and logged in a tamper-evident chain):"]
    for e in evidence:
        lines.append(f"  #{e['seq']} {e['captured_at']} | {e.get('source_url') or 'no URL'} | "
                     f"sha256={e.get('sha256') or 'not stored'} | {e.get('note') or ''}")
    lines += ["", "Automated analysis (indicative only, not conclusive) is attached where available.",
              "Request: urgent removal of the content, preservation of related logs, and action against the uploader.",
              "", "[Add your name, contact details and any usernames/phone numbers of the suspected sender]"]
    return "\n".join(lines)
