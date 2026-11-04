"""WebAuthn / passkey factor (Touch ID, Face ID, Windows Hello, security keys) via py_webauthn.

The biometric stays on the device. The authenticator checks it (userVerification="required") and signs
the server's challenge with a key that never leaves the device; the server verifies that signature with
the public key it stored at registration, plus origin, RP ID, the UV flag and the sign counter.

Binding to the action: the assertion challenge is 16 random bytes followed by
SHA-256("phishguard-webauthn-v1|" + pending_id + "|" + confirm_digest). The authenticator's signature
covers clientDataJSON, which contains that challenge, so a signed assertion names exactly one pending
action and its digest. The gateway keeps one outstanding challenge per pending action and deletes it
on first use (success or failure), so an assertion can't be replayed for the same or another action.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .factors import EnrollmentError
from .kv import KV
from .policy import ct_equal, normalize_user

MAX_CREDENTIALS = 10


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def action_binding(pending_id: str, digest: str) -> bytes:
    return hashlib.sha256(f"phishguard-webauthn-v1|{pending_id}|{digest}".encode()).digest()


class WebAuthnManager:
    method = "webauthn"

    def __init__(
        self,
        kv: KV | None = None,
        clock=time.time,
        rp_id: str = "localhost",
        rp_name: str = "PhishGuard",
        origins: tuple[str, ...] = ("http://localhost:8000",),
        challenge_seconds: int = 120,
    ):
        self._kv = kv or KV()
        self._clock = clock
        self.rp_id, self.rp_name, self.origins = rp_id, rp_name, list(origins)
        self.challenge_seconds = challenge_seconds
        self._lock = threading.Lock()

    # -- enrollment -----------------------------------------------------------------------------
    def credentials(self, user: str) -> list[dict[str, Any]]:
        return self._kv.get("webauthn", normalize_user(user), [])

    def is_enrolled(self, user: str) -> bool:
        return bool(self.credentials(user))

    def _user_handle(self, user: str) -> bytes:
        u = normalize_user(user)
        h = self._kv.get("webauthn_handle", u)
        if h is None:  # random, not derived from the name (the spec asks for no personal data in it)
            h = b64u(secrets.token_bytes(32))
            self._kv.put("webauthn_handle", u, h)
        return unb64u(h)

    def registration_options(self, user: str) -> dict[str, Any]:
        u = normalize_user(user)
        with self._lock:
            challenge = secrets.token_bytes(32)
            opts = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_name=u,
                user_id=self._user_handle(u),
                challenge=challenge,
                timeout=self.challenge_seconds * 1000,
                attestation=AttestationConveyancePreference.NONE,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.PREFERRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                exclude_credentials=[PublicKeyCredentialDescriptor(id=unb64u(c["id"])) for c in self.credentials(u)],
            )
            self._kv.put(
                "webauthn_reg", u, {"challenge": b64u(challenge), "exp": self._clock() + self.challenge_seconds}
            )
        return json.loads(options_to_json(opts))

    def register(self, user: str, credential: dict[str, Any]) -> str:
        """Verify navigator.credentials.create() output and store the public key. Returns the credential id."""
        u = normalize_user(user)
        with self._lock:
            state = self._kv.get("webauthn_reg", u)
            self._kv.delete("webauthn_reg", u)  # single use, even if verification fails
            if not state or self._clock() > state["exp"]:
                raise EnrollmentError("no registration in progress (request options first) or it expired")
            try:
                v = verify_registration_response(
                    credential=credential,
                    expected_challenge=unb64u(state["challenge"]),
                    expected_rp_id=self.rp_id,
                    expected_origin=self.origins,
                    require_user_verification=True,
                )
            except Exception as e:  # library raises several types for malformed input
                raise EnrollmentError(f"registration not verified: {type(e).__name__}") from None
            cid = b64u(v.credential_id)
            if self._kv.get("webauthn_owner", cid) is not None:
                raise EnrollmentError("credential already registered")
            creds = self.credentials(u)
            if len(creds) >= MAX_CREDENTIALS:
                raise EnrollmentError("too many credentials for this user")
            transports = []
            resp = credential.get("response") if isinstance(credential, dict) else None
            if isinstance(resp, dict) and isinstance(resp.get("transports"), list):
                transports = [str(t)[:20] for t in resp["transports"][:6]]
            creds.append(
                {
                    "id": cid,
                    "public_key": b64u(v.credential_public_key),
                    "sign_count": v.sign_count,
                    "aaguid": v.aaguid,
                    "transports": transports,
                    "created": self._clock(),
                }
            )
            self._kv.put("webauthn", u, creds)
            self._kv.put("webauthn_owner", cid, u)
        return cid

    # -- assertion (approval) -------------------------------------------------------------------
    def assertion_options(self, user: str, pending_id: str, digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Options for navigator.credentials.get() and the server-side state the gateway keeps."""
        challenge = secrets.token_bytes(16) + action_binding(pending_id, digest)
        opts = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge,
            timeout=self.challenge_seconds * 1000,
            allow_credentials=[PublicKeyCredentialDescriptor(id=unb64u(c["id"])) for c in self.credentials(user)],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        state = {"challenge": b64u(challenge), "exp": self._clock() + self.challenge_seconds}
        return json.loads(options_to_json(opts)), state

    def verify_assertion(
        self, user: str, credential: Any, state: dict[str, Any] | None, pending_id: str, digest: str
    ) -> tuple[bool, str]:
        """(ok, reason). `state` is the challenge the gateway just removed from the pending action."""
        if not state:
            return False, "no_challenge"
        if self._clock() > state["exp"]:
            return False, "challenge_expired"
        expected = unb64u(state["challenge"])
        if not hmac.compare_digest(expected[16:], action_binding(pending_id, digest)):
            return False, "wrong_action_binding"
        if not isinstance(credential, dict):
            return False, "malformed"
        u = normalize_user(user)
        with self._lock:
            creds = self.credentials(u)
            cred = next((c for c in creds if ct_equal(c["id"], credential.get("id", ""))), None)
            if cred is None:
                return False, "unknown_credential"  # includes another user's passkey
            try:
                v = verify_authentication_response(
                    credential=credential,
                    expected_challenge=expected,
                    expected_rp_id=self.rp_id,
                    expected_origin=self.origins,
                    credential_public_key=unb64u(cred["public_key"]),
                    credential_current_sign_count=int(cred["sign_count"]),
                    require_user_verification=True,
                )
            except Exception as e:  # InvalidAuthenticationResponse, or parse errors on hostile input
                msg = str(e).lower()
                if "sign count" in msg:
                    return False, "sign_count_not_increased"  # possible cloned authenticator
                if "origin" in msg:
                    return False, "wrong_origin"
                if "rp id" in msg:
                    return False, "wrong_rp_id"
                if "user verification" in msg:
                    return False, "user_not_verified"
                if "challenge" in msg:
                    return False, "wrong_challenge"
                return False, "bad_assertion"
            if getattr(v, "user_verified", True) is False:  # older py_webauthn lacks the field; UV is enforced above
                return False, "user_not_verified"
            handle = (credential.get("response") or {}).get("userHandle")
            if handle and not ct_equal(handle, b64u(self._user_handle(u))):
                return False, "user_handle_mismatch"
            cred["sign_count"] = v.new_sign_count
            cred["last_used"] = self._clock()
            self._kv.put("webauthn", u, creds)
        return True, "ok"
