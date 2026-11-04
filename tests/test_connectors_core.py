"""Connector core: secrets, HTTP retry/backoff/refresh, OAuth providers, checkpoint + idempotent scanner."""

import base64
import json
import logging
import os
import stat

import httpx
import pytest

from phishguard.agent import PhishingAgent
from phishguard.config import Settings
from phishguard.connectors import Batch, CheckpointStore, MailboxConnector, RawMessage, Rejected, Scanner
from phishguard.connectors import auth as A
from phishguard.connectors.http import ProviderError, RateLimited, RetryingClient, parse_retry_after
from phishguard.connectors.secrets import (
    REPO_ROOT,
    SecretError,
    TokenStore,
    install_redaction,
    load_json_secret,
    load_secret,
    redact,
    register,
)
from phishguard.llm import MockLLM

FIX = REPO_ROOT / "tests" / "fixtures"


# ------------------------------------------------------------------ secrets
def test_secret_from_env_or_private_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PG_TEST_SECRET", "env-secret-value-1")
    assert load_secret(env="PG_TEST_SECRET") == "env-secret-value-1"
    f = tmp_path / "s.txt"
    f.write_text("file-secret-value-2\n")
    f.chmod(0o600)
    assert load_secret(file=f) == "file-secret-value-2"
    f.chmod(0o644)
    with pytest.raises(SecretError, match="chmod 600"):
        load_secret(file=f)
    with pytest.raises(SecretError):
        load_secret(env="PG_TEST_MISSING")
    assert load_secret(env="PG_TEST_MISSING", required=False) is None


def test_secret_files_inside_repo_refused():
    with pytest.raises(SecretError, match="inside the repository"):
        load_secret(file=REPO_ROOT / "README.md")
    with pytest.raises(SecretError):
        TokenStore(REPO_ROOT / "tokens.json")


def test_token_store_is_private_and_atomic(tmp_path):
    st = TokenStore(tmp_path / "tok" / "gmail.json")
    st.save({"refresh_token": "1//refresh-abcdef"})
    assert stat.S_IMODE(os.stat(st.path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(st.path.parent).st_mode) == 0o700
    assert st.load() == {"refresh_token": "1//refresh-abcdef"}
    assert "1//refresh-abcdef" not in redact("token is 1//refresh-abcdef")
    assert not [p for p in st.path.parent.iterdir() if p.name.startswith(".tok-")]


def test_redaction_in_logs(caplog):
    register("super-secret-token-xyz")
    install_redaction()
    lg = logging.getLogger("phishguard.connectors")
    with caplog.at_level(logging.INFO, logger="phishguard"):
        lg.info("calling with %s", "Bearer super-secret-token-xyz")
    assert "super-secret-token-xyz" not in caplog.text and "***" in caplog.text


def test_json_secret_registers_inner_values(tmp_path):
    f = tmp_path / "client.json"
    f.write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "GOCSPX-inner-secret"}}))
    f.chmod(0o600)
    load_json_secret(file=f)
    assert "GOCSPX-inner-secret" not in redact("x GOCSPX-inner-secret y")


# ------------------------------------------------------------------ HTTP client
def _client(handler, auth=None, hosts=("api.example.com",), **kw):
    sleeps = []
    c = RetryingClient(httpx.Client(transport=httpx.MockTransport(handler)), auth, hosts, sleep=sleeps.append, **kw)
    return c, sleeps


def test_retry_after_seconds_and_http_date():
    assert parse_retry_after("7") == 7.0
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", now=1445412470.0) == pytest.approx(10.0)
    assert parse_retry_after("garbage") is None and parse_retry_after(None) is None


def test_429_and_503_are_retried_honoring_retry_after():
    seq = [httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(503), httpx.Response(200, json={"ok": 1})]
    c, sleeps = _client(lambda r: seq.pop(0))
    assert c.get_json("https://api.example.com/x") == {"ok": 1}
    assert sleeps[0] == 3.0 and len(sleeps) == 2


def test_gmail_403_rate_limit_is_retried_but_other_403_is_not():
    rl = {"error": {"code": 403, "errors": [{"reason": "userRateLimitExceeded"}]}}
    seq = [httpx.Response(403, json=rl), httpx.Response(200, json={})]
    c, sleeps = _client(lambda r: seq.pop(0))
    c.get_json("https://api.example.com/x")
    assert len(sleeps) == 1
    c2, _ = _client(lambda r: httpx.Response(403, json={"error": {"code": 403, "status": "PERMISSION_DENIED"}}))
    with pytest.raises(ProviderError) as e:
        c2.get_json("https://api.example.com/x")
    assert e.value.status == 403 and "PERMISSION_DENIED" in str(e.value)


def test_long_retry_after_raises_instead_of_blocking():
    c, _ = _client(lambda r: httpx.Response(429, headers={"Retry-After": "3600"}), max_delay=60)
    with pytest.raises(RateLimited) as e:
        c.get_json("https://api.example.com/x")
    assert e.value.retry_after == 3600


def test_retries_are_bounded():
    c, sleeps = _client(lambda r: httpx.Response(503), max_retries=3)
    with pytest.raises(RateLimited):
        c.get_json("https://api.example.com/x")
    assert len(sleeps) == 3


class CountingToken(A.TokenProvider):
    def __init__(self):
        super().__init__()
        self.n = 0

    def _fetch(self):
        self.n += 1
        return {"access_token": f"tok-{self.n}-abcdefgh", "expires_in": 3600}


def test_401_refreshes_token_once():
    seen = []

    def h(r):
        seen.append(r.headers["Authorization"])
        return httpx.Response(401) if len(seen) == 1 else httpx.Response(200, json={"ok": True})

    tok = CountingToken()
    c, _ = _client(h, auth=tok)
    assert c.get_json("https://api.example.com/x") == {"ok": True}
    assert seen == ["Bearer tok-1-abcdefgh", "Bearer tok-2-abcdefgh"]
    c2, _ = _client(lambda r: httpx.Response(401), auth=CountingToken())
    with pytest.raises(ProviderError) as e:
        c2.get_json("https://api.example.com/x")
    assert e.value.status == 401


def test_foreign_or_plain_http_hosts_refused():
    c, _ = _client(lambda r: httpx.Response(200, json={}), auth=CountingToken())
    for url in ("https://evil.example/steal", "http://api.example.com/x"):
        with pytest.raises(ProviderError, match="refusing"):
            c.get_json(url)
    assert c.requests == []  # nothing was sent, so no token left the process


def test_capped_download():
    big = b"x" * 5000
    c, _ = _client(lambda r: httpx.Response(200, content=big))
    assert c.get_bytes_capped("https://api.example.com/raw", 10_000) == big
    assert c.get_bytes_capped("https://api.example.com/raw", 1000) is None


# ------------------------------------------------------------------ OAuth providers
def _token_server(log):
    def h(r):
        form = dict(x.split("=", 1) for x in r.content.decode().split("&"))
        log.append((r.url.path, form))
        return httpx.Response(
            200,
            json={"access_token": f"at-{len(log)}-zzzzzz", "expires_in": 3600, "refresh_token": "rt-rotated-123456"},
        )

    return httpx.Client(transport=httpx.MockTransport(h))


def test_refresh_provider_caches_and_rotates(tmp_path):
    log, now = [], [1000.0]
    store = TokenStore(tmp_path / "t.json")
    store.save({"refresh_token": "rt-original-12345"})
    p = A.RefreshTokenProvider(
        _token_server(log), A.GOOGLE_TOKEN_URL, "cid", store, "csecret-123456", clock=lambda: now[0]
    )
    assert p.token() == p.token() and len(log) == 1  # cached
    assert log[0][1]["grant_type"] == "refresh_token" and log[0][1]["refresh_token"] == "rt-original-12345"
    now[0] += 3600  # expired
    p.token()
    assert len(log) == 2 and store.load()["refresh_token"] == "rt-rotated-123456"


def test_refresh_provider_without_token_explains(tmp_path):
    p = A.RefreshTokenProvider(_token_server([]), A.GOOGLE_TOKEN_URL, "cid", TokenStore(tmp_path / "none.json"))
    with pytest.raises(A.AuthError, match="--authorize"):
        p.token()


def _rsa():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return k, pem.decode()


def test_service_account_jwt_is_valid_rs256_with_subject():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    k, pem = _rsa()
    log = []
    key = {"client_email": "sa@proj.iam.gserviceaccount.com", "private_key": pem, "private_key_id": "kid1"}
    sa = A.GoogleServiceAccount(_token_server(log), key, subject="alice@example.com", clock=lambda: 1_000_000)
    sa.token()
    form = log[0][1]
    assert form["grant_type"] == "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
    from urllib.parse import unquote

    jwt = unquote(form["assertion"])
    h, c, s = jwt.split(".")
    pad = lambda x: x + "=" * (-len(x) % 4)  # noqa: E731
    claims = json.loads(base64.urlsafe_b64decode(pad(c)))
    assert claims["sub"] == "alice@example.com" and claims["scope"] == A.GMAIL_READ_SCOPE
    assert claims["aud"] == A.GOOGLE_TOKEN_URL and claims["exp"] - claims["iat"] == 3600
    k.public_key().verify(base64.urlsafe_b64decode(pad(s)), f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert pem.split("\n")[1] not in redact(pem)  # private key registered for redaction


def test_client_credentials():
    log = []
    p = A.ClientCredentials(_token_server(log), "contoso.onmicrosoft.com", "app-id", "app-secret-123456")
    p.token()
    path, form = log[0]
    assert path == "/contoso.onmicrosoft.com/oauth2/v2.0/token" and form["grant_type"] == "client_credentials"
    assert "graph.microsoft.com" in form["scope"]


def test_device_code_flow_handles_pending_and_slow_down(tmp_path):
    replies = [
        httpx.Response(
            200,
            json={
                "device_code": "dc-123456",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://microsoft.com/devicelogin",
                "interval": 1,
                "expires_in": 600,
            },
        ),
        httpx.Response(400, json={"error": "authorization_pending"}),
        httpx.Response(400, json={"error": "slow_down"}),
        httpx.Response(
            200, json={"access_token": "at-dev-123456", "refresh_token": "rt-dev-123456", "scope": "Mail.Read"}
        ),
    ]
    out, sleeps = [], []
    store = TokenStore(tmp_path / "ms.json")
    A.device_code_flow(
        httpx.Client(transport=httpx.MockTransport(lambda r: replies.pop(0))),
        "common",
        "cid",
        A.GRAPH_READ_SCOPES,
        store,
        out=out.append,
        sleep=sleeps.append,
    )
    assert store.load()["refresh_token"] == "rt-dev-123456"
    assert sleeps == [1.0, 1.0, 6.0]  # slow_down adds 5 s
    printed = "\n".join(out)
    assert "ABCD-EFGH" in printed and "rt-dev-123456" not in printed and "at-dev-123456" not in printed


def test_installed_app_flow_pkce_state_and_storage(tmp_path):
    seen = {}

    def h(r):
        seen.update(dict(x.split("=", 1) for x in r.content.decode().split("&")))
        return httpx.Response(200, json={"access_token": "at-ia-123456", "refresh_token": "rt-ia-123456"})

    def wait(url, state):
        from urllib.parse import parse_qs, urlparse

        q = parse_qs(urlparse(url).query)
        assert (
            q["scope"] == [A.GMAIL_READ_SCOPE]
            and q["code_challenge_method"] == ["S256"]
            and q["access_type"] == ["offline"]
        )
        seen["state_ok"] = q["state"] == [state]
        return "auth-code-123456"

    store = TokenStore(tmp_path / "g.json")
    out = []
    A.google_installed_app_flow(
        httpx.Client(transport=httpx.MockTransport(h)),
        {"installed": {"client_id": "cid", "client_secret": "cs-123456"}},
        (A.GMAIL_READ_SCOPE,),
        store,
        out=out.append,
        wait_for_code=wait,
    )
    assert seen["state_ok"] and seen["code"] == "auth-code-123456" and len(seen["code_verifier"]) >= 43
    assert store.load()["refresh_token"] == "rt-ia-123456" and "rt-ia-123456" not in "\n".join(out)


def test_loopback_server_rejects_wrong_state():
    import threading
    import urllib.request

    srv = A._LoopbackServer(0, "good-state", timeout=5)
    t = threading.Thread(target=lambda: setattr(srv, "result", srv.wait()))
    t.start()
    for state, want in (("bad", 400), ("good-state", 200)):
        try:
            code = urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/?code=c-123456&state={state}").status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == want
    t.join(5)
    assert srv.result == "c-123456"


# ------------------------------------------------------------------ scanner + idempotency
class FakeConnector(MailboxConnector):
    provider = "fake"

    def __init__(self, messages, rejected=()):
        super().__init__("fake-box")
        self.messages, self.rejected, self.calls = messages, list(rejected), []

    def list_new_messages(self, cursor, limit=50):
        self.calls.append(cursor)
        start = (cursor or {}).get("pos", 0) if cursor else max(0, len(self.messages) - limit)
        page = self.messages[start : start + limit]
        return Batch(page, self.rejected, {"pos": start + len(page)})


def _scanner(conn, store=None):
    s = Settings(executives=("David Chen",))
    return Scanner(conn, PhishingAgent(MockLLM(), s), store or CheckpointStore(), s.phishing_threshold)


def test_scanner_feeds_parse_and_agent_and_is_idempotent():
    msgs = [RawMessage(f"id{i}", p.read_bytes()) for i, p in enumerate(sorted(FIX.glob("*.eml")))]
    conn = FakeConnector(msgs, [Rejected("huge1", "too_large", 30_000_000)])
    store = CheckpointStore()
    sc = _scanner(conn, store)
    r1 = sc.scan(limit=100)
    assert len(r1.verdicts) == 11 and {v.status for v in r1.verdicts} == {"scanned", "too_large"}
    phish = {v.provider_id for v in r1.verdicts if v.is_phishing}
    assert {"id0", "id1", "id2"}.isdisjoint(phish) and len(phish) >= 5  # benign_* sort first
    conn.messages = msgs + [msgs[0]]  # same bytes delivered again under a new id
    conn.messages[-1] = RawMessage("id-dup", msgs[0].raw)
    store.set_cursor("fake-box", None or {})  # force a full re-list
    r2 = sc.scan(limit=100)
    assert r2.verdicts == [] and r2.duplicates == 12  # 10 by id + huge1 by id + 1 by content hash
    assert store.seen_count("fake-box") == 10 * 2 + 1  # id + sha256 per scanned message, id for rejected


def test_cursor_advances_and_persists(tmp_path):
    msgs = [
        RawMessage(f"m{i}", (FIX / "benign_internal_plain.eml").read_bytes().replace(b"sync-001", f"s{i}".encode()))
        for i in range(5)
    ]
    db = str(tmp_path / "scan.db")
    conn = FakeConnector(msgs)
    _scanner(conn, CheckpointStore(db)).scan(limit=2)
    assert CheckpointStore(db).get_cursor("fake-box") == {"pos": 5}  # initial scan = newest 2, cursor at end
    conn.messages = msgs + [RawMessage("m5", msgs[0].raw.replace(b"s0", b"s5"))]
    r = _scanner(conn, CheckpointStore(db)).scan(limit=2)
    assert [v.provider_id for v in r.verdicts] == ["m5"] and conn.calls[-1] == {"pos": 5}


def test_malformed_mime_and_size_limit_do_not_crash():
    junk = RawMessage("junk", b"\x00\xff\xfe garbage without headers")
    deep = "Content-Type: text/plain\n\nhi\n"
    for i in range(300):
        deep = f'Content-Type: multipart/mixed; boundary="b{i}"\n\n--b{i}\n{deep}\n--b{i}--\n'
    bomb = RawMessage("bomb", ("From: a@b.c\n" + deep).encode())
    big = RawMessage("big", b"Subject: x\n\n" + b"a" * 2_000_001)
    r = _scanner(FakeConnector([junk, bomb, big])).scan()
    st = {v.provider_id: v.status for v in r.verdicts}
    assert st["bomb"] == "unparseable" and st["big"] == "too_large" and st["junk"] in ("scanned", "unparseable")


def test_verdict_public_view_has_no_content():
    msgs = [RawMessage("p", (FIX / "phish_bec_auth_fail.eml").read_bytes())]
    v = _scanner(FakeConnector(msgs)).scan().verdicts[0]
    pub = json.dumps(v.public())
    assert v.subject and v.subject not in pub and "david.chen" not in pub.lower()
