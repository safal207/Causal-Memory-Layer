from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


MemoryKind = Literal["observation", "decision", "outcome"]


class MemoryCreate(BaseModel):
    session_id: str = Field(min_length=1, max_length=160)
    kind: MemoryKind
    content: str = Field(min_length=3, max_length=4000)
    tags: list[str] = Field(default_factory=list, max_length=30)
    status: str = Field(default="active", min_length=1, max_length=80)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    parent_memory_id: str | None = None

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, tags: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for tag in tags:
            value = tag.strip().casefold()
            if not value or value in seen:
                continue
            if len(value) > 80:
                raise ValueError("tag must be 80 characters or fewer")
            seen.add(value)
            normalized.append(value)
        return normalized


class MemoryRecord(MemoryCreate):
    id: str
    created_at: datetime


class DecisionRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=160)
    proposed_action: str = Field(min_length=3, max_length=4000)
    tags: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, tags: list[str]) -> list[str]:
        return MemoryCreate.normalize_tags(tags)
