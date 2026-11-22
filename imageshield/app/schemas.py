from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, HttpUrl

ContentType = Literal["ai_generated_or_edited", "intimate_or_sexual", "impersonation", "harassment", "other"]
Platform = Literal["instagram", "facebook", "whatsapp", "x", "tiktok", "youtube", "snapchat", "telegram", "other"]


class RiskQuestionnaire(BaseModel):
    profile_public: bool = False
    posts_face_photos: bool = False
    unknown_followers: bool = False
    shares_location: bool = False
    previously_harassed: bool = False
    conflict_with_person_holding_images: bool = False
    public_figure_or_creator: bool = False
    has_found_edited_copy: bool = False
    is_minor: bool = False
    public_photo_count: int = Field(0, ge=0, le=100_000)


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    platform: Platform | None = None
    content_type: ContentType | None = None
    is_minor: bool = False


class EvidenceMeta(BaseModel):
    kind: str = Field("screenshot", max_length=40)
    source_url: HttpUrl | None = None
    platform: Platform | None = None
    note: str | None = Field(None, max_length=1000)
