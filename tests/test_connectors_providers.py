"""Gmail, Microsoft Graph and IMAP connectors against in-process fakes (no real network)."""

import pytest

from phishguard.agent import PhishingAgent
from phishguard.config import Settings
from phishguard.connectors import CheckpointStore, Scanner
from phishguard.connectors.auth import StaticToken, TokenProvider
from phishguard.connectors.gmail import API_HOST, GmailConnector
from phishguard.connectors.graph import GRAPH_HOST, GraphConnector
from phishguard.connectors.http import ProviderError, RateLimited, RetryingClient
from phishguard.connectors.imap import ImapConnector, InsecureTransport
from phishguard.connectors.presets import PRESETS
from phishguard.connectors.secrets import REPO_ROOT
from phishguard.llm import MockLLM
from tests.fakes import TOKEN, FakeGmail, FakeGraph, FakeImapServer, ImapState, self_signed_tls

FIX = REPO_ROOT / "tests" / "fixtures"
EMLS = [p.read_bytes() for p in sorted(FIX.glob("*.eml"))]


def mail(i: int) -> bytes:
    base = (FIX / "benign_internal_plain.eml").read_bytes()
    return base.replace(b"sync-001", f"msg-{i:04d}".encode()).replace(b"Thursday", f"day {i}".encode())


def rc(fake, host, auth=None, **kw):
    sleeps = []
    return RetryingClient(fake.client(), auth or StaticToken(TOKEN), [host], sleep=sleeps.append, **kw), sleeps


def scanner(conn, store=None):
    s = Settings(executives=("David Chen",))
    return Scanner(conn, PhishingAgent(MockLLM(), s), store or CheckpointStore(), s.phishing_threshold)


# ================================================================== Gmail
@pytest.fixture
def gmail():
    g = FakeGmail()
    for i in range(7):
        g.add(f"g{i}", mail(i))
    return g


def test_gmail_initial_scan_paginates_and_sets_history_cursor(gmail):
    http, _ = rc(gmail, API_HOST)
    conn = GmailConnector(http, "work")
    import phishguard.connectors.gmail as gm

    gm.PAGE, old = 3, gm.PAGE  # force several list pages
    try:
        b = conn.list_new_messages(None, limit=5)
    finally:
        gm.PAGE = old
    assert [m.provider_id for m in b.messages] == ["g2", "g3", "g4", "g5", "g6"]  # newest 5, oldest first
    assert b.cursor == {"history_id": "1007"} and b.messages[0].raw == mail(2)
    assert sum(1 for m, p in gmail.calls if p.endswith("/messages")) == 2


def test_gmail_incremental_history_with_pages(gmail):
    http, _ = rc(gmail, API_HOST)
    conn = GmailConnector(http, "work")
    c = conn.list_new_messages(None, 3).cursor
    for i in range(7, 12):
        gmail.add(f"g{i}", mail(i))
    gmail.add("sent1", mail(99), labels=("SENT",))  # not inbox: ignored
    b = conn.list_new_messages(c, 50)
    assert [m.provider_id for m in b.messages] == ["g7", "g8", "g9", "g10", "g11"]
    assert b.cursor == {"history_id": str(gmail.hid)}
    assert conn.list_new_messages(b.cursor, 50).messages == []


def test_gmail_partial_history_keeps_old_cursor(gmail):
    http, _ = rc(gmail, API_HOST)
    conn = GmailConnector(http, "work")
    c = conn.list_new_messages(None, 1).cursor
    for i in range(7, 13):
        gmail.add(f"g{i}", mail(i))
    b = conn.list_new_messages(c, 2)
    assert len(b.messages) == 2 and b.cursor == c  # more waiting: don't advance past unseen mail


def test_gmail_expired_history_falls_back(gmail):
    http, _ = rc(gmail, API_HOST)
    conn = GmailConnector(http, "work")
    gmail.min_history = 5000
    b = conn.list_new_messages({"history_id": "1001"}, 2)
    assert "history expired" in b.notes[0] and len(b.messages) == 2


def test_gmail_large_message_not_downloaded(gmail):
    gmail.add("huge", b"Subject: x\n\nsmall body", size=30_000_000)
    http, _ = rc(gmail, API_HOST)
    b = GmailConnector(http, "work").list_new_messages(None, 1)
    assert [(r.provider_id, r.reason) for r in b.rejected] == [("huge", "too_large")]
    assert not any("format=raw" in p for _, p in gmail.calls)  # only minimal metadata fetched


def test_gmail_429_backoff_and_token_refresh(gmail):
    import httpx

    class Rotating(TokenProvider):
        n = 0

        def _fetch(self):
            Rotating.n += 1
            return {"access_token": TOKEN if Rotating.n > 1 else "stale-token-000000", "expires_in": 3600}

    gmail.forced = [httpx.Response(429, headers={"Retry-After": "2"})]
    http, sleeps = rc(gmail, API_HOST, auth=Rotating())
    b = GmailConnector(http, "work").list_new_messages(None, 2)
    assert len(b.messages) == 2 and sleeps == [2.0] and Rotating.n == 2


def test_gmail_read_connector_only_reads(gmail):
    http, _ = rc(gmail, API_HOST)
    conn = GmailConnector(http, "work")
    c = conn.list_new_messages(None, 7).cursor
    gmail.add("g7", mail(7))
    conn.list_new_messages(c, 10)
    assert gmail.methods() == {"GET"}
    assert all("INBOX" in m["labels"] for m in gmail.msgs.values() if m["labels"] != {"SENT"})


def test_gmail_end_to_end_scan_idempotent():
    g = FakeGmail()
    for i, raw in enumerate(EMLS):
        g.add(f"f{i}", raw)
    http, _ = rc(g, API_HOST)
    store = CheckpointStore()
    sc = scanner(GmailConnector(http, "work"), store)
    r1 = sc.scan(limit=20)
    assert len(r1.verdicts) == 10 and sum(v.is_phishing for v in r1.verdicts) >= 5
    g.add("again", EMLS[4])  # the same message delivered again
    r2 = sc.scan(limit=20)
    assert r2.verdicts == [] and r2.duplicates == 1


def test_gmail_watch(gmail):
    http, _ = rc(gmail, API_HOST)
    assert GmailConnector(http, "work").watch("projects/p/topics/t")["historyId"]


# ================================================================== Graph
@pytest.fixture
def graph():
    g = FakeGraph()
    for i in range(5):
        g.add(f"m{i}", mail(i))
    return g


def test_graph_initial_scan_and_delta_link(graph):
    http, _ = rc(graph, GRAPH_HOST)
    conn = GraphConnector(http, "o365")
    b = conn.list_new_messages(None, 3)
    assert [m.provider_id for m in b.messages] == ["m2", "m3", "m4"] and b.messages[2].raw == mail(4)
    assert b.cursor["delta_link"].endswith("$deltatoken=d-5")


def test_graph_incremental_delta_paginated(graph):
    http, _ = rc(graph, GRAPH_HOST)
    conn = GraphConnector(http, "o365")
    c = conn.list_new_messages(None, 2).cursor
    for i in range(5, 10):
        graph.add(f"m{i}", mail(i))
    graph.add("moved", mail(77), folder="junkemail")  # shows up as @removed: skipped
    b = conn.list_new_messages(c, 50)
    assert [m.provider_id for m in b.messages] == ["m5", "m6", "m7", "m8", "m9"]
    assert b.cursor["delta_link"].endswith("d-11")
    assert conn.list_new_messages(b.cursor, 50).messages == []


def test_graph_expired_delta_resets(graph):
    http, _ = rc(graph, GRAPH_HOST)
    conn = GraphConnector(http, "o365")
    c = conn.list_new_messages(None, 1).cursor
    graph.expired_tokens.add("d-5")
    b = conn.list_new_messages(c, 2)
    assert "expired" in b.notes[0] and len(b.messages) == 2


def test_graph_refuses_foreign_next_link(graph):
    http, _ = rc(graph, GRAPH_HOST)
    conn = GraphConnector(http, "o365")
    with pytest.raises(ProviderError, match="non-allow-listed"):
        conn.list_new_messages(
            {"delta_link": "https://attacker.example/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=d-1"}, 5
        )
    assert all(p.startswith("/v1.0") for _, p in graph.calls) or graph.calls == []


def test_graph_large_mime_aborted(graph):
    graph.add("big", b"Subject: x\n\n" + b"a" * 2_100_000)
    http, _ = rc(graph, GRAPH_HOST)
    b = GraphConnector(http, "o365").list_new_messages(None, 1)
    assert [(r.provider_id, r.reason) for r in b.rejected] == [("big", "too_large")]


def test_graph_503_then_ok_and_bounded(graph):
    import httpx

    graph.forced = [httpx.Response(503), httpx.Response(503, headers={"Retry-After": "1"})]
    http, sleeps = rc(graph, GRAPH_HOST)
    assert len(GraphConnector(http, "o365").list_new_messages(None, 1).messages) == 1 and sleeps[1] == 1.0
    graph.forced = [httpx.Response(429)] * 10
    http, _ = rc(graph, GRAPH_HOST, max_retries=2)
    with pytest.raises(RateLimited):
        GraphConnector(http, "o365").list_new_messages(None, 1)


def test_graph_app_user_path_and_subscription(graph):
    http, _ = rc(graph, GRAPH_HOST)
    conn = GraphConnector(http, "o365", user="alice@contoso.com")
    assert conn.base.endswith("/users/alice@contoso.com")
    sub = GraphConnector(http, "o365").subscribe("https://pg.example/webhooks/graph", "client-state-abcdef")
    assert sub["changeType"] == "created" and sub["resource"] == "me/mailFolders('inbox')/messages"


def test_graph_read_connector_only_reads(graph):
    http, _ = rc(graph, GRAPH_HOST)
    conn = GraphConnector(http, "o365")
    c = conn.list_new_messages(None, 5).cursor
    graph.add("m5", mail(5))
    conn.list_new_messages(c, 5)
    assert graph.methods() == {"GET"}
    assert {m["folder"] for m in graph.msgs.values()} == {"inbox"}


# ================================================================== IMAP
def imap_conn(srv, **kw):
    kw.setdefault("password", "app-pass-123456")
    return ImapConnector(
        "icloud", "127.0.0.1", "user@example.com", port=srv.port, tls="none", allow_plaintext=True, **kw
    )


def test_imap_plaintext_refused_without_dev_flag():
    with pytest.raises(InsecureTransport):
        ImapConnector("x", "imap.example.com", "u", password="p", tls="none")
    with pytest.raises(ValueError):
        ImapConnector("x", "imap.example.com", "u")  # no credential


def test_imap_initial_incremental_and_read_only():
    st = ImapState()
    for i in range(6):
        st.add(mail(i))
    with FakeImapServer(st) as srv:
        conn = imap_conn(srv)
        b = conn.list_new_messages(None, 3)
        assert [m.provider_id for m in b.messages] == ["42:4", "42:5", "42:6"] and b.messages[0].raw == mail(3)
        assert b.cursor == {"uidvalidity": 42, "last_uid": 6}
        assert conn.list_new_messages(b.cursor, 10).messages == []  # "7:*" matches UID 6; filtered out
        for i in range(6, 9):
            st.add(mail(i))
        b2 = conn.list_new_messages(b.cursor, 2)
        assert [m.provider_id for m in b2.messages] == ["42:7", "42:8"] and b2.cursor["last_uid"] == 8
        assert [m.provider_id for m in conn.list_new_messages(b2.cursor, 10).messages] == ["42:9"]
    assert "EXAMINE" in st.commands and "SELECT" not in st.commands
    assert not any(c.split()[-1] in ("STORE", "EXPUNGE", "MOVE", "COPY") for c in st.commands)
    assert all(not fl for _, _, fl in st.folders["INBOX"])  # BODY.PEEK[]: not even \Seen was set


def test_imap_uidvalidity_change_restarts_without_rescanning():
    st = ImapState()
    for raw in EMLS[:4]:
        st.add(raw)
    with FakeImapServer(st) as srv:
        store = CheckpointStore()
        sc = scanner(imap_conn(srv), store)
        assert len(sc.scan(10).verdicts) == 4
        st.renumber()
        r = sc.scan(10)
        assert r.verdicts == [] and r.duplicates == 4 and "UIDVALIDITY changed" in r.notes[0]
        assert store.get_cursor("icloud")["uidvalidity"] == 43


def test_imap_size_limit_and_malformed():
    st = ImapState()
    st.add(b"Subject: big\r\n\r\n" + b"a" * 2_000_100)
    st.add(b"\x00\xff garbage")
    with FakeImapServer(st) as srv:
        b = imap_conn(srv).list_new_messages(None, 10)
        assert [r.reason for r in b.rejected] == ["too_large"] and len(b.messages) == 1
        v = scanner(imap_conn(srv)).scan(10).verdicts
        assert {x.status for x in v} <= {"too_large", "scanned", "unparseable"}


def test_imap_bad_password_and_xoauth2():
    st = ImapState()
    st.add(mail(1))
    with FakeImapServer(st) as srv:
        with pytest.raises(ProviderError, match="login"):
            imap_conn(srv, password="wrong-password").list_new_messages(None, 1)
        conn = ImapConnector(
            "o",
            "127.0.0.1",
            "user@example.com",
            token_provider=StaticToken(TOKEN),
            port=srv.port,
            tls="none",
            allow_plaintext=True,
        )
        assert len(conn.list_new_messages(None, 1).messages) == 1
    assert "AUTHENTICATE" in st.commands


def test_imap_id_command_for_netease():
    st = ImapState()
    with FakeImapServer(st) as srv:
        imap_conn(srv, send_id=True).list_new_messages(None, 1)
    assert st.sent_id and PRESETS["163"].send_id


def test_imap_implicit_tls_verifies_certificate(tmp_path):
    import ssl

    server_ctx, client_ctx = self_signed_tls(tmp_path)
    st = ImapState()
    st.add(mail(1))
    with FakeImapServer(st, tls_ctx=server_ctx) as srv:
        ok = ImapConnector(
            "t", "127.0.0.1", "user@example.com", password="app-pass-123456", port=srv.port, ssl_context=client_ctx
        )
        assert len(ok.list_new_messages(None, 1).messages) == 1
        untrusted = ImapConnector("t", "127.0.0.1", "user@example.com", password="app-pass-123456", port=srv.port)
        with pytest.raises(ssl.SSLError):  # default context: system CAs only, so the fake cert is rejected
            untrusted.list_new_messages(None, 1)


def test_presets_cover_common_providers():
    assert {"gmail", "outlook", "icloud", "yahoo", "fastmail", "qq", "163", "zoho"} <= set(PRESETS)
    assert all(p.port == 993 for p in PRESETS.values())
    assert PRESETS["outlook"].auth == "xoauth2" and PRESETS["gmail"].oauth == "google"
