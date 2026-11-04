"""Push notifications: Graph validationToken + clientState, Gmail Pub/Sub OIDC JWT verification."""

import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.connectors import CheckpointStore
from phishguard.connectors.webhooks import GoogleCerts, InvalidToken, build_router, verify_google_jwt

AUD = "https://pg.example.com/webhooks/gmail"
SA = "push@proj.iam.gserviceaccount.com"
NOW = 1_800_000_000


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa

    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = k.public_key().public_numbers()
    jwk = {
        "kid": "k1",
        "kty": "RSA",
        "alg": "RS256",
        "n": _b64(pub.n.to_bytes(256, "big")),
        "e": _b64(pub.e.to_bytes(3, "big")),
    }
    return k, {"keys": [jwk]}


def sign(key, claims, header=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    h = _b64(json.dumps(header or {"alg": "RS256", "kid": "k1", "typ": "JWT"}).encode())
    c = _b64(json.dumps(claims).encode())
    sig = key.sign(f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{c}.{_b64(sig)}"


def claims(**kw):
    base = {
        "iss": "https://accounts.google.com",
        "aud": AUD,
        "email": SA,
        "email_verified": True,
        "iat": NOW - 10,
        "exp": NOW + 3000,
    }
    return {**base, **kw}


@pytest.fixture
def app(keypair, monkeypatch):
    monkeypatch.setenv("PG_GRAPH_CS", "graph-client-state-123456")
    store = CheckpointStore()
    cfg = {
        "webhooks": {
            "graph": [{"mailbox": "o365", "client_state_env": "PG_GRAPH_CS"}],
            "gmail": {"audience": AUD, "service_account": SA, "mailboxes": {"User@Example.com": "work"}},
        }
    }
    a = FastAPI()
    a.include_router(build_router(cfg, store, GoogleCerts(lambda: keypair[1], clock=lambda: NOW), clock=lambda: NOW))
    return TestClient(a), store


# ------------------------------------------------------------------ Graph
def test_graph_validation_handshake_echoes_plain_text(app):
    c, _ = app
    r = c.post("/webhooks/graph?validationToken=Validation%3A+Testing+client+application")
    assert r.status_code == 200 and r.text == "Validation: Testing client application"
    assert r.headers["content-type"].startswith("text/plain") and r.headers["x-content-type-options"] == "nosniff"


def test_graph_notification_with_valid_client_state_triggers_scan(app):
    c, store = app
    body = {"value": [{"subscriptionId": "s", "clientState": "graph-client-state-123456", "changeType": "created"}]}
    assert c.post("/webhooks/graph", json=body).status_code == 202
    assert store.pop_triggers() == ["o365"] and store.pop_triggers() == []


@pytest.mark.parametrize("cs", ["wrong", "", None, "graph-client-state-12345"])
def test_graph_bad_client_state_rejected(app, cs):
    c, store = app
    r = c.post("/webhooks/graph", json={"value": [{"clientState": cs}]})
    assert r.status_code == 403 and store.pop_triggers() == []


def test_graph_garbage_body(app):
    c, _ = app
    assert (
        c.post("/webhooks/graph", content=b"not json", headers={"content-type": "application/json"}).status_code == 400
    )


# ------------------------------------------------------------------ Gmail / Pub/Sub
def push(c, token, email="user@example.com"):
    data = base64.b64encode(json.dumps({"emailAddress": email, "historyId": "123"}).encode()).decode()
    h = {"Authorization": f"Bearer {token}"} if token else {}
    return c.post("/webhooks/gmail", json={"message": {"data": data, "messageId": "1"}, "subscription": "s"}, headers=h)


def test_gmail_valid_push_triggers_scan(app, keypair):
    c, store = app
    assert push(c, sign(keypair[0], claims())).status_code == 204
    assert store.pop_triggers() == ["work"]
    assert push(c, sign(keypair[0], claims()), email="other@example.com").status_code == 204
    assert store.pop_triggers() == []  # unknown address: acked, ignored


def test_gmail_missing_token(app):
    assert push(app[0], None).status_code == 401


@pytest.mark.parametrize(
    "bad",
    [
        {"aud": "https://evil.example/webhooks/gmail"},
        {"iss": "https://evil.example"},
        {"email": "attacker@evil.iam.gserviceaccount.com"},
        {"email_verified": False},
        {"exp": NOW - 3600},
        {"iat": NOW + 3600},
    ],
)
def test_gmail_bad_claims_rejected(app, keypair, bad):
    c, store = app
    assert push(c, sign(keypair[0], claims(**bad))).status_code == 403 and store.pop_triggers() == []


def test_gmail_forged_signatures_rejected(app, keypair):
    from cryptography.hazmat.primitives.asymmetric import rsa

    c, store = app
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    good = sign(keypair[0], claims())
    h, cl, _ = good.split(".")
    forged = [
        sign(other, claims()),  # attacker's own key, our kid
        f"{h}.{cl}.",  # no signature
        f"{_b64(json.dumps({'alg': 'none', 'kid': 'k1'}).encode())}.{cl}.",  # alg=none
        f"{_b64(json.dumps({'alg': 'HS256', 'kid': 'k1'}).encode())}.{cl}.AAAA",  # alg confusion
        sign(keypair[0], claims(), {"alg": "RS256", "kid": "unknown"}),
        "garbage",
    ]
    for t in forged:
        assert push(c, t).status_code == 403, t[:40]
    assert store.pop_triggers() == []


def test_verify_function_directly(keypair):
    certs = GoogleCerts(lambda: keypair[1])
    assert verify_google_jwt(sign(keypair[0], claims()), AUD, SA, certs, NOW)["email"] == SA
    with pytest.raises(InvalidToken):
        verify_google_jwt(sign(keypair[0], claims()), AUD, SA, certs, NOW + 10_000)


def test_certs_rotation_refetch_is_rate_limited(keypair):
    calls, now = [], [NOW]

    def fetch():
        calls.append(1)
        return keypair[1] if len(calls) > 1 else {"keys": [{**keypair[1]["keys"][0], "kid": "old"}]}

    certs = GoogleCerts(fetch, clock=lambda: now[0])
    with pytest.raises(InvalidToken):  # kid k1 not published yet, cache is fresh
        verify_google_jwt(sign(keypair[0], claims()), AUD, SA, certs, NOW)
    for _ in range(50):  # a flood of unknown kids within the minute: no extra fetches
        with pytest.raises(InvalidToken):
            certs.key("forged")
    assert len(calls) == 1
    now[0] += 61  # Google rotated keys meanwhile
    assert verify_google_jwt(sign(keypair[0], claims()), AUD, SA, certs, now[0])
    assert len(calls) == 2


# ------------------------------------------------------------------ mounting in the API
def test_api_mounts_webhooks_only_when_configured(tmp_path, monkeypatch):
    from phishguard.api import create_app
    from phishguard.config import Settings

    monkeypatch.delenv("PHISHGUARD_MAILBOX_CONFIG", raising=False)
    plain = TestClient(create_app(Settings()))
    assert plain.post("/webhooks/graph?validationToken=x").status_code == 404
    cfg = tmp_path / "m.yaml"
    monkeypatch.setenv("PG_GRAPH_CS", "graph-client-state-123456")
    cfg.write_text(
        f"state_db: {tmp_path / 's.db'}\nmailboxes: []\nwebhooks:\n  graph:\n    - {{mailbox: o365, client_state_env: PG_GRAPH_CS}}\n"
    )
    monkeypatch.setenv("PHISHGUARD_MAILBOX_CONFIG", str(cfg))
    c = TestClient(create_app(Settings(api_keys=("k",), allow_unauthenticated=False)))
    assert c.post("/webhooks/graph?validationToken=hello").text == "hello"  # no API key needed for the provider
    assert c.post("/analyze", json={}).status_code == 401  # the rest of the API still requires one
