"""Gmail and Microsoft Graph connectors and OAuth providers, against offline fakes."""

import base64
import json
import os
import time

import httpx
import pytest

from phishguard.connectors import gmail, graph
from phishguard.connectors.base import MessageRef, OverPrivilegedCredential
from phishguard.connectors.config import authorize, build_connector, token_store
from phishguard.connectors.http import HttpClient
from phishguard.connectors.oauth import (
    GMAIL_READ_SCOPE,
    GoogleRefreshToken,
    GoogleServiceAccount,
    MicrosoftClientCredentials,
    MicrosoftRefreshToken,
    OAuthError,
    exchange_google_code,
    google_auth_url,
    microsoft_device_code_flow,
)
from phishguard.connectors.secrets import Secret, TokenStore
from phishguard.readonly import EmlTooLarge
from phishguard.readonly.eml import MAX_RAW_BYTES
from tests.mail_fakes import GMAIL_MODIFY, FakeGmail, FakeGraph, make_raw


def gmail_conn(fake: FakeGmail, clock=time.time, **kw):
    c = fake.client()
    auth = GoogleRefreshToken(
        HttpClient(c),
        "cid.apps.googleusercontent.com",
        Secret("GOCSPX-client-secret-1"),
        Secret(fake.refresh_token),
        clock=clock,
    )
    return gmail.GmailConnector(HttpClient(c, auth=auth, auth_hosts=gmail.AUTH_HOSTS, sleep=lambda s: None), **kw)


def graph_conn(fake: FakeGraph, tmp_path, mailbox=None, **kw):
    c = fake.client()
    store = TokenStore(tmp_path / "tok.json")
    store.put("graph:read", {"refresh_token": next(iter(fake.refresh_tokens))})
    auth = MicrosoftRefreshToken(
        HttpClient(c), "common", "client-id-1", store, "graph:read", ["https://graph.microsoft.com/Mail.Read"]
    )
    http = HttpClient(c, auth=auth, auth_hosts=graph.AUTH_HOSTS, sleep=lambda s: None)
    return graph.GraphConnector(http, mailbox=mailbox, **kw), store


# ---------------------------------------------------------------------------------- Gmail
def test_gmail_list_recent_paginates_newest_first():
    fake = FakeGmail()
    ids = [fake.add(make_raw(f"m{i}", n=i)) for i in range(7)]
    conn = gmail_conn(fake, page_size=3)
    got = [r.provider_id for r in conn.list_recent(5)]
    assert got == list(reversed(ids))[:5]
    pages = [r for r in fake.requests if r.url.path.endswith("/messages")]
    assert len(pages) == 2 and "pageToken" in str(pages[1].url)


def test_gmail_incremental_history_cursor_with_pagination():
    fake = FakeGmail()
    fake.add(make_raw("old"))
    conn = gmail_conn(fake, page_size=2)
    refs, cur = conn.list_new(None)
    assert refs == [] and cur == str(fake.hid)  # first run: start from now, no backlog
    new = [fake.add(make_raw(f"n{i}", n=i)) for i in range(5)]
    fake.add(make_raw("draft"), labels=("DRAFT",))
    refs, cur2 = conn.list_new(cur)
    assert [r.provider_id for r in refs] == new  # oldest first, drafts excluded, 3 pages
    assert int(cur2) > int(cur)
    assert conn.list_new(cur2)[0] == []


def test_gmail_expired_history_falls_back_to_recent():
    fake = FakeGmail()
    ids = [fake.add(make_raw(f"m{i}", n=i)) for i in range(3)]
    fake.min_history = 10**9
    conn = gmail_conn(fake, page_size=10)
    refs, cur = conn.list_new("1001")
    assert [r.provider_id for r in refs] == ids and cur == str(fake.hid)


def test_gmail_fetch_raw_decodes_base64url():
    fake = FakeGmail()
    raw = make_raw("Hi", body="ünïcode body")
    mid = fake.add(raw)
    assert gmail_conn(fake).fetch_raw(MessageRef(mid)) == raw
    assert "format=raw" in str(fake.requests[-1].url)


def test_gmail_large_message_rejected_with_existing_limit():
    fake = FakeGmail()
    mid = fake.add(b"Subject: big\r\n\r\n" + b"A" * (MAX_RAW_BYTES + 10))
    with pytest.raises(EmlTooLarge):
        gmail_conn(fake).fetch_raw(MessageRef(mid))


def test_gmail_malformed_payload():
    from phishguard.connectors.base import MalformedMessage

    fake = FakeGmail()
    mid = fake.add(make_raw())
    fake.raw_override[mid] = "!!!not base64!!!"
    with pytest.raises(MalformedMessage):
        gmail_conn(fake).fetch_raw(MessageRef(mid))
    with pytest.raises(MalformedMessage):
        gmail_conn(fake).fetch_raw(MessageRef("../../evil"))


def test_gmail_token_refresh_on_expiry_and_on_401():
    fake = FakeGmail()
    fake.add(make_raw())
    now = [1000.0]
    conn = gmail_conn(fake, clock=lambda: now[0])
    conn.list_recent(1)
    conn.list_recent(1)
    assert len(fake.token_requests) == 1  # cached
    now[0] += 3600  # past expiry (minus skew)
    conn.list_recent(1)
    assert len(fake.token_requests) == 2
    fake.valid_tokens.clear()  # server-side revocation -> 401 -> one refresh
    conn.list_recent(1)
    assert len(fake.token_requests) == 3
    assert all(f["grant_type"] == "refresh_token" for f in fake.token_requests)


def test_gmail_429_backoff_during_listing():
    fake = FakeGmail()
    mid = fake.add(make_raw())
    conn = gmail_conn(fake)
    conn.list_recent(1)
    fake.queue = [httpx.Response(429, headers={"Retry-After": "1"})]
    assert [r.provider_id for r in conn.list_recent(1)] == [mid]
    assert conn.http.retries == 1


def test_gmail_refuses_overprivileged_read_token():
    fake = FakeGmail(scope=GMAIL_MODIFY)
    fake.add(make_raw())
    with pytest.raises(OverPrivilegedCredential, match="gmail.modify"):
        gmail_conn(fake).list_recent(1)
    assert gmail_conn(fake, allow_overprivileged=True).list_recent(1)


def test_gmail_service_account_jwt_is_signed_and_scoped():
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    info = {
        "client_email": "pg@proj.iam.gserviceaccount.com",
        "private_key": pem,
        "private_key_id": "k1",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    fake = FakeGmail()
    sa = GoogleServiceAccount(HttpClient(fake.client()), info, "alice@corp.example", [GMAIL_READ_SCOPE])
    tok = sa.token()
    form = fake.token_requests[0]
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer" and tok
    claims = jwt.decode(
        form["assertion"], key.public_key(), algorithms=["RS256"], audience="https://oauth2.googleapis.com/token"
    )
    assert claims["sub"] == "alice@corp.example" and claims["scope"] == GMAIL_READ_SCOPE
    assert claims["exp"] - claims["iat"] <= 3600
    with pytest.raises(OAuthError, match="token_uri"):
        GoogleServiceAccount(HttpClient(fake.client()), {**info, "token_uri": "https://evil.example/token"}, "a@b", [])


def test_gmail_build_from_env_with_files_outside_repo(tmp_path):
    fake = FakeGmail()
    mid = fake.add(make_raw())
    cfile = tmp_path / "client.json"
    cfile.write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "GOCSPX-zzzzzzzzzz"}}))
    os.chmod(cfile, 0o600)
    env = {"PHISHGUARD_GMAIL_CLIENT_FILE": str(cfile), "PHISHGUARD_TOKEN_FILE": str(tmp_path / "t.json")}
    token_store(env).put("gmail:read", {"refresh_token": fake.refresh_token})
    conn = build_connector("gmail", env, client=fake.client())
    assert [r.provider_id for r in conn.list_recent(5)] == [mid]
    with pytest.raises(OAuthError, match="--authorize"):
        build_connector("gmail", {**env, "PHISHGUARD_TOKEN_FILE": str(tmp_path / "empty.json")}, client=fake.client())


def test_google_loopback_exchange_checks_state_and_uses_pkce():
    url = google_auth_url("cid", "http://127.0.0.1:5555/", [GMAIL_READ_SCOPE], "st", "chal")
    assert "code_challenge_method=S256" in url and "access_type=offline" in url and "gmail.readonly" in url
    fake = FakeGmail()
    fake.refresh_token = "x"

    def handler(req):
        form = dict(p.split("=", 1) for p in req.content.decode().split("&"))
        assert form["grant_type"] == "authorization_code" and form["code_verifier"] == "verifier"
        return httpx.Response(
            200, json={"access_token": "ya29.abcdefghijk", "refresh_token": "1//new-refresh-abcdefgh"}
        )

    http = HttpClient(httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(OAuthError, match="state mismatch"):
        exchange_google_code(http, "cid", Secret("sec-123456"), {"code": "c", "state": "forged"}, "st", "verifier", "r")
    data = exchange_google_code(
        http, "cid", Secret("sec-123456"), {"code": "4/abc", "state": "st"}, "st", "verifier", "r"
    )
    assert data["refresh_token"] == "1//new-refresh-abcdefgh"


# ---------------------------------------------------------------------------------- Graph
def test_graph_delta_cursor_pagination_and_incremental(tmp_path):
    fake = FakeGraph()
    fake.add(make_raw("old"))
    conn, _ = graph_conn(fake, tmp_path)
    refs, cur = conn.list_new(None)
    assert refs == [] and "$deltatoken=" in cur
    new = [fake.add(make_raw(f"n{i}", n=i)) for i in range(5)]
    refs, cur2 = conn.list_new(cur)
    assert [r.provider_id for r in refs] == new  # 3 pages of 2
    assert cur2 != cur and conn.list_new(cur2)[0] == []
    prefer = [r.headers.get("prefer", "") for r in fake.requests if r.url.host == "graph.microsoft.com"]
    assert all('IdType="ImmutableId"' in p for p in prefer)


def test_graph_expired_delta_token_resets(tmp_path):
    fake = FakeGraph()
    ids = [fake.add(make_raw(f"m{i}", n=i)) for i in range(3)]
    conn, _ = graph_conn(fake, tmp_path)
    refs, cur = conn.list_new("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=gone")
    assert [r.provider_id for r in refs] == ids and "$deltatoken=" in cur


def test_graph_refuses_foreign_paging_links(tmp_path):
    fake = FakeGraph()
    fake.add(make_raw())
    conn, _ = graph_conn(fake, tmp_path)
    refs, cur = conn.list_new("https://evil.example.net/v1.0/me/messages/delta?$deltatoken=x")
    assert all(r.url.host != "evil.example.net" for r in fake.requests)  # reset instead of following it


def test_graph_fetch_mime_and_size_limit(tmp_path):
    fake = FakeGraph()
    raw = make_raw("Hi")
    mid = fake.add(raw)
    big = fake.add(b"Subject: x\r\n\r\n" + b"B" * (MAX_RAW_BYTES + 1))
    conn, _ = graph_conn(fake, tmp_path)
    assert conn.fetch_raw(MessageRef(mid)) == raw
    assert fake.requests[-1].url.path.endswith("/$value")
    with pytest.raises(EmlTooLarge):
        conn.fetch_raw(MessageRef(big))


def test_graph_refresh_token_rotation_is_persisted(tmp_path):
    fake = FakeGraph()
    fake.add(make_raw())
    conn, store = graph_conn(fake, tmp_path)
    conn.list_recent(1)
    stored = store.get("graph:read")["refresh_token"]
    assert stored in fake.refresh_tokens and "rotated" in stored
    assert oct(os.stat(store.path).st_mode & 0o777) == "0o600"


def test_graph_app_only_client_credentials_and_role_check(tmp_path):
    fake = FakeGraph(roles=["Mail.Read"], delegated_scope=None)
    fake.add(make_raw())
    c = fake.client()
    auth = MicrosoftClientCredentials(HttpClient(c), "contoso.onmicrosoft.com", "cid", Secret("app-secret-value-1"))
    conn = graph.GraphConnector(HttpClient(c, auth=auth, auth_hosts=graph.AUTH_HOSTS), mailbox="alice@contoso.com")
    assert len(conn.list_recent(5)) == 1
    assert "/v1.0/users/alice@contoso.com/" in fake.requests[-1].url.path
    assert fake.token_requests[0]["scope"] == "https://graph.microsoft.com/.default"
    over = FakeGraph(roles=["Mail.Read", "Mail.ReadWrite"], delegated_scope=None)
    c2 = over.client()
    auth2 = MicrosoftClientCredentials(HttpClient(c2), "contoso.onmicrosoft.com", "cid", Secret("app-secret-value-1"))
    with pytest.raises(OverPrivilegedCredential, match="mail.readwrite"):
        graph.GraphConnector(HttpClient(c2, auth=auth2, auth_hosts=graph.AUTH_HOSTS), mailbox="a@b.c").list_recent(1)
    with pytest.raises(OAuthError):
        MicrosoftClientCredentials(HttpClient(c), "common", "cid", Secret("x" * 10))


def test_device_code_flow_handles_pending_and_slow_down(tmp_path):
    fake = FakeGraph()
    shown, sleeps = [], []
    data = microsoft_device_code_flow(
        HttpClient(fake.client()),
        "common",
        "cid",
        ["https://graph.microsoft.com/Mail.Read"],
        prompt=shown.append,
        sleep=sleeps.append,
    )
    assert data["refresh_token"] and "ABCD-EFGH" in shown[0]
    assert sleeps == [5, 5, 10]  # slow_down adds 5 s
    assert "DAQABAAEAAAD-device-code-secret" not in shown[0]
    assert "offline_access" in fake.token_requests[0]["scope"]


def test_authorize_graph_stores_refresh_token_with_0600(tmp_path):
    fake = FakeGraph()
    fake.device_polls = [None]
    env = {"PHISHGUARD_GRAPH_CLIENT_ID": "cid", "PHISHGUARD_TOKEN_FILE": str(tmp_path / "cfg" / "tokens.json")}
    key = authorize("graph", env, prompt=lambda s: None, client=fake.client())
    assert key == "graph:read"
    p = tmp_path / "cfg" / "tokens.json"
    assert oct(os.stat(p).st_mode & 0o777) == "0o600" and oct(os.stat(p.parent).st_mode & 0o777) == "0o700"
    assert "refresh-original" in p.read_text()
    assert "Mail.Read" in fake.token_requests[0]["scope"] and "ReadWrite" not in fake.token_requests[0]["scope"]


def test_graph_subscription_validation():
    fake = FakeGraph()
    conn = graph.GraphConnector(HttpClient(fake.client()))
    with pytest.raises(ValueError):
        conn.subscribe("http://insecure.example/hook", "x" * 32)
    with pytest.raises(ValueError):
        conn.subscribe("https://ok.example/hook", "short")


def test_jwt_claims_helper_ignores_opaque_tokens():
    from phishguard.connectors.oauth import _jwt_claims_unverified

    assert _jwt_claims_unverified("EwBwA8l6BAAU-opaque") == {}
    payload = base64.urlsafe_b64encode(b'{"scp":"Mail.Read"}').rstrip(b"=").decode()
    assert _jwt_claims_unverified(f"a.{payload}.c") == {"scp": "Mail.Read"}
