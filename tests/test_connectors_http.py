"""HttpClient: 429/503 backoff with Retry-After, Gmail 403 rate reasons, 401 refresh, bounded reads."""

import httpx
import pytest

from phishguard.connectors.base import ConnectorError
from phishguard.connectors.http import HttpClient, HttpError, ResponseTooLarge, parse_retry_after


class Tok:
    def __init__(self):
        self.n = 0
        self.invalidated = 0

    def token(self):
        self.n += 1
        return f"tok-{self.invalidated}"

    def invalidate(self):
        self.invalidated += 1


def client(responses, auth=None, **kw):
    seen = []

    def handler(req):
        seen.append(req)
        r = responses.pop(0)
        return r(req) if callable(r) else r

    sleeps = []
    c = HttpClient(
        httpx.Client(transport=httpx.MockTransport(handler)),
        auth=auth,
        auth_hosts=frozenset({"api.example.com"}),
        sleep=sleeps.append,
        rng=lambda: 0.5,
        clock=lambda: 1_000_000.0,
        **kw,
    )
    return c, seen, sleeps


URL = "https://api.example.com/x"


def test_429_honours_retry_after_seconds():
    c, seen, sleeps = client(
        [httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, json={"ok": 1})], auth=Tok()
    )
    assert c.get_json(URL) == {"ok": 1}
    assert sleeps == [7.0] and len(seen) == 2 and c.retries == 1


def test_503_retry_after_http_date_and_cap():
    c, _, sleeps = client(
        [
            httpx.Response(503, headers={"Retry-After": "Mon, 12 Jan 1970 13:46:40 GMT"}),  # 1_000_000 + 0
            httpx.Response(503, headers={"Retry-After": "86400"}),  # capped
            httpx.Response(200, json={}),
        ],
        max_backoff=60,
    )
    c.get_json(URL)
    assert sleeps == [0.0, 60.0]


def test_exponential_backoff_without_retry_after():
    c, _, sleeps = client([httpx.Response(429)] * 3 + [httpx.Response(200, json={})], base_backoff=1.0)
    c.get_json(URL)
    assert sleeps == [0.75, 1.5, 3.0]  # 2**n * (0.5 + 0.5/2)


def test_gmail_403_rate_limit_reason_is_retried_but_permission_403_is_not():
    rate = httpx.Response(403, json={"error": {"code": 403, "errors": [{"reason": "userRateLimitExceeded"}]}})
    c, _, sleeps = client([rate, httpx.Response(200, json={"a": 1})])
    assert c.get_json(URL) == {"a": 1} and len(sleeps) == 1
    denied = httpx.Response(403, json={"error": {"code": 403, "errors": [{"reason": "insufficientPermissions"}]}})
    c, _, sleeps = client([denied])
    with pytest.raises(HttpError) as e:
        c.get_json(URL)
    assert e.value.status == 403 and e.value.code == "insufficientPermissions" and sleeps == []


def test_retries_are_bounded():
    c, seen, _ = client([httpx.Response(429)] * 10, max_retries=3)
    with pytest.raises(HttpError, match="retries exhausted"):
        c.get_json(URL)
    assert len(seen) == 4


def test_401_invalidates_token_and_retries_once():
    tok = Tok()
    c, seen, _ = client([httpx.Response(401), httpx.Response(200, json={"x": 1})], auth=tok)
    assert c.get_json(URL) == {"x": 1}
    assert tok.invalidated == 1
    assert [r.headers["authorization"] for r in seen] == ["Bearer tok-0", "Bearer tok-1"]
    c, _, _ = client([httpx.Response(401), httpx.Response(401)], auth=Tok())
    with pytest.raises(HttpError) as e:
        c.get_json(URL)
    assert e.value.status == 401


def test_token_is_never_sent_to_another_host_or_over_http():
    c, seen, _ = client([httpx.Response(200, json={})], auth=Tok())
    for bad in ("https://evil.example.net/steal", "http://api.example.com/x"):
        with pytest.raises(ConnectorError, match="refusing to send credentials"):
            c.get_json(bad)
    assert seen == []


def test_bounded_download_by_content_length_and_by_stream():
    c, _, _ = client([httpx.Response(200, content=b"x" * 100)])
    with pytest.raises(ResponseTooLarge):
        c.get_bytes(URL, max_bytes=50)

    def chunked(_req):
        return httpx.Response(200, stream=httpx.ByteStream(b"y" * 100))  # no content-length check possible

    c, _, _ = client([chunked])
    with pytest.raises(ResponseTooLarge):
        c.get_bytes(URL, max_bytes=50)
    c, _, _ = client([httpx.Response(200, content=b"z" * 50)])
    assert c.get_bytes(URL, max_bytes=50) == b"z" * 50


def test_error_messages_never_include_body_or_query():
    body = {"error": {"code": 500, "message": "secret-in-body Bearer abcdefghijklmnop"}}
    c, _, _ = client([httpx.Response(500, json=body)])
    with pytest.raises(HttpError) as e:
        c.get_json(URL, params={"pageToken": "cursor-secret"})
    assert "secret-in-body" not in str(e.value) and "cursor-secret" not in str(e.value)


def test_network_errors_back_off_then_fail_cleanly():
    def boom(req):
        raise httpx.ConnectError("down", request=req)

    c, _, sleeps = client([boom, boom, httpx.Response(200, json={"ok": True})])
    assert c.get_json(URL) == {"ok": True} and len(sleeps) == 2
    c, _, _ = client([boom] * 3, max_retries=2)
    with pytest.raises(ConnectorError, match="network error"):
        c.get_json(URL)


def test_parse_retry_after():
    assert parse_retry_after(None, 0) is None
    assert parse_retry_after("12", 0) == 12.0
    assert parse_retry_after("garbage", 0) is None
