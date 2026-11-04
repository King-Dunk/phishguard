"""IMAP presets for common providers. Check the provider's own help page if a login fails: these
settings change rarely, but they do change."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ImapPreset:
    host: str
    port: int = 993
    auth: str = "app_password"  # app_password | xoauth2 | both
    oauth: str | None = None  # "google" | "microsoft" when XOAUTH2 is available
    send_id: bool = False  # some providers require the IMAP ID command (RFC 2971) before reading
    notes: str = ""


PRESETS: dict[str, ImapPreset] = {
    "gmail": ImapPreset(
        "imap.gmail.com",
        auth="both",
        oauth="google",
        notes="Prefer the Gmail API connector. IMAP: app password (needs 2-Step Verification) or XOAUTH2, "
        "which requires Google's full https://mail.google.com/ scope.",
    ),
    "outlook": ImapPreset(
        "outlook.office365.com",
        auth="xoauth2",
        oauth="microsoft",
        notes="Prefer the Graph connector. Basic-auth passwords are retired for Exchange Online; "
        "XOAUTH2 needs the IMAP.AccessAsUser.All permission.",
    ),
    "icloud": ImapPreset(
        "imap.mail.me.com",
        notes="App-specific password from appleid.apple.com (Sign-In and Security). Apple's docs give "
        "the part of the address before @ as the user name.",
    ),
    "yahoo": ImapPreset("imap.mail.yahoo.com", notes="App password: Account Security -> Generate app password."),
    "aol": ImapPreset("imap.aol.com", notes="App password: Account Security -> Generate app password."),
    "fastmail": ImapPreset("imap.fastmail.com", notes="App password: Settings -> Privacy & Security -> App passwords."),
    "zoho": ImapPreset(
        "imap.zoho.com",
        notes="Enable IMAP access in Zoho Mail settings; use an app-specific password with 2FA. "
        "EU/IN accounts: imap.zoho.eu / imap.zoho.in.",
    ),
    "qq": ImapPreset(
        "imap.qq.com",
        notes="Enable IMAP in QQ Mail settings and use the generated authorization code (授权码), not the QQ password.",
    ),
    "163": ImapPreset(
        "imap.163.com",
        send_id=True,
        notes="Enable IMAP and use the client authorization code (授权码). "
        "NetEase rejects clients that don't send IMAP ID.",
    ),
    "126": ImapPreset("imap.126.com", send_id=True, notes="As 163: authorization code and IMAP ID."),
    "yandex": ImapPreset("imap.yandex.com", notes="Enable IMAP in settings; use an app password."),
}
