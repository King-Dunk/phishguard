"""Shared plain data models. Imports nothing from readonly/ or mutating/."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

AuthResult = Literal["pass", "fail", "none"]
Url = Annotated[str, Field(max_length=2048)]
FileName = Annotated[str, Field(max_length=256)]


class Attachment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(default="", max_length=256)
    content_type: str = Field(default="", max_length=128)
    size: int = Field(default=0, ge=0)


class DisplayedLink(BaseModel):
    """An HTML anchor: what the reader sees (`text`) vs where it really goes (`href`)."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(default="", max_length=512)
    href: str = Field(default="", max_length=2048)


class EmailMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(max_length=128)
    timestamp: datetime
    sender_name: str = Field(default="", max_length=256)
    sender_email: str = Field(max_length=320)
    reply_to: str | None = Field(default=None, max_length=320)
    return_path: str | None = Field(default=None, max_length=320)
    recipient: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=1000)
    body: str = Field(default="", max_length=20000)
    links: list[Url] = Field(default_factory=list, max_length=100)
    attachments: list[FileName] = Field(default_factory=list, max_length=50)
    attachment_meta: list[Attachment] = Field(default_factory=list, max_length=50)
    link_pairs: list[DisplayedLink] = Field(default_factory=list, max_length=100)
    list_mail: bool = False  # List-Id / List-Unsubscribe / List-Post / Precedence: list|bulk|junk
    hidden_text: str = Field(default="", max_length=5000)  # CSS-hidden HTML text
    header_anomalies: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=10)
    sender_reputation: float | None = Field(default=None, ge=0, le=1)
    sender_domain_age_days: int | None = Field(default=None, ge=0)
    spf: AuthResult = "none"
    dkim: AuthResult = "none"
    dmarc: AuthResult = "none"
