"""Shared plain data models. Imports nothing from readonly/ or mutating/."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AuthResult = Literal["pass", "fail", "none"]


class EmailMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(max_length=128)
    timestamp: datetime
    sender_name: str = Field(default="", max_length=256)
    sender_email: str = Field(max_length=320)
    reply_to: str | None = Field(default=None, max_length=320)
    recipient: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=1000)
    body: str = Field(default="", max_length=20000)
    links: list[str] = Field(default_factory=list, max_length=100)
    attachments: list[str] = Field(default_factory=list, max_length=50)
    sender_reputation: float | None = Field(default=None, ge=0, le=1)
    sender_domain_age_days: int | None = Field(default=None, ge=0)
    spf: AuthResult = "none"
    dkim: AuthResult = "none"
    dmarc: AuthResult = "none"
