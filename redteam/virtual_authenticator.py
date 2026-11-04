"""A software WebAuthn authenticator (ES256, "none" attestation) for tests, the red team and the CLI demo.

It produces exactly the JSON a browser returns from navigator.credentials.create()/get(), so the
server-side verification (py_webauthn) runs unmodified. Knobs let an attacker misbehave: wrong origin,
no user verification, a rolled-back sign counter (cloned key), or replaying an old assertion.

This is NOT a real Touch ID: it proves the server's checks, not a particular device or browser.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

UP, UV, AT = 0x01, 0x04, 0x40


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class VirtualAuthenticator:
    def __init__(self, origin: str = "http://localhost:8000", rp_id: str = "localhost"):
        self.origin, self.rp_id = origin, rp_id
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(32)
        self.counter = 0
        self.user_handle: bytes | None = None

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False},
            separators=(",", ":"),
        ).encode()

    def create(self, public_key: dict[str, Any], origin: str | None = None, uv: bool = True) -> dict[str, Any]:
        """navigator.credentials.create({publicKey}) -> RegistrationResponseJSON."""
        rp_id = public_key.get("rp", {}).get("id", self.rp_id)
        self.user_handle = unb64u(public_key["user"]["id"])
        flags = UP | AT | (UV if uv else 0)
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        auth += b"\x00" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        cd = self._client_data("webauthn.create", public_key["challenge"], origin)
        return {
            "id": b64u(self.cred_id),
            "rawId": b64u(self.cred_id),
            "type": "public-key",
            "response": {"clientDataJSON": b64u(cd), "attestationObject": b64u(att), "transports": ["internal"]},
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(
        self,
        public_key: dict[str, Any],
        origin: str | None = None,
        uv: bool = True,
        counter: int | None = None,
        rp_id: str | None = None,
    ) -> dict[str, Any]:
        """navigator.credentials.get({publicKey}) -> AuthenticationResponseJSON (user approved)."""
        if counter is None:
            self.counter += 1
            counter = self.counter
        rp = rp_id or public_key.get("rpId", self.rp_id)
        auth = hashlib.sha256(rp.encode()).digest() + bytes([UP | (UV if uv else 0)]) + struct.pack(">I", counter)
        cd = self._client_data("webauthn.get", public_key["challenge"], origin)
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        resp = {"clientDataJSON": b64u(cd), "authenticatorData": b64u(auth), "signature": b64u(sig)}
        if self.user_handle:
            resp["userHandle"] = b64u(self.user_handle)
        return {
            "id": b64u(self.cred_id),
            "rawId": b64u(self.cred_id),
            "type": "public-key",
            "response": resp,
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
