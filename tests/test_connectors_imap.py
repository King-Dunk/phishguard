"""IMAP connector against a real-socket fake server (TLS with a throwaway certificate)."""

import ssl

import pytest

from phishguard.connectors.base import ConnectorError, MessageRef
from phishguard.connectors.config import build_connector
from phishguard.connectors.imap import PRESETS, ImapConnector, _utf7_imap, quote_mailbox, xoauth2_string
from phishguard.connectors.oauth import StaticToken
from phishguard.connectors.secrets import Secret
from phishguard.readonly import EmlTooLarge
from phishguard.readonly.eml import MAX_RAW_BYTES
from tests.mail_fakes import FakeImapServer, make_raw, self_signed_cert

PW = "app-password-abcd-efgh"


@pytest.fixture
def tls(tmp_path):
    cert, key = self_signed_cert(tmp_path)
    ctx = ssl.create_default_context(cafile=cert)
    return (cert, key), ctx


@pytest.fixture
def server(tls):
    s = FakeImapServer(tls_files=tls[0])
    yield s
    s.close()


def conn(server, ctx, **kw):
    return ImapConnector("127.0.0.1", server.user, password=Secret(PW), port=server.port, ssl_context=ctx, **kw)


def test_tls_login_cursor_and_incremental_listing(server, tls):
    server.add(make_raw("old"))
    c = conn(server, tls[1])
    refs, cur = c.list_new(None)
    assert refs == [] and cur == "7:1"
    u2 = server.add(make_raw("a", n=2))
    u3 = server.add(make_raw("b", n=3))
    refs, cur2 = c.list_new(cur)
    assert [r.provider_id for r in refs] == [f"7:{u2}", f"7:{u3}"] and cur2 == f"7:{u3}"
    assert c.list_new(cur2)[0] == []  # "UID n:*" returns the top UID even when nothing is new; filtered
    assert c.fetch_raw(refs[0]) == make_raw("a", n=2)
    c.close()


def test_read_only_examine_and_peek_never_change_the_mailbox(server, tls):
    uid = server.add(make_raw("x"))
    c = conn(server, tls[1])
    for r in c.list_recent(5):
        c.fetch_raw(r)
    c.close()
    cmds = " ".join(server.commands).upper()
    assert "EXAMINE" in cmds and " SELECT " not in cmds
    assert "BODY.PEEK[]" in cmds
    for verb in ("STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "CREATE", "DELETE"):
        assert f" {verb} " not in cmds and f"UID {verb}" not in cmds
    assert "\\Seen" not in server.folders["INBOX"]["msgs"][uid]["flags"]
    assert PW not in " ".join(server.commands)


def test_uidvalidity_change_resets_cursor(server, tls):
    for i in range(3):
        server.add(make_raw(f"m{i}", n=i))
    c = conn(server, tls[1], page_size=10)
    _, cur = c.list_new(None)
    c.close()
    server.renumber()
    c2 = conn(server, tls[1], page_size=10)
    refs, cur2 = c2.list_new(cur)
    assert cur2.startswith("8:") and len(refs) == 3  # rescanned; the scanner dedupes by content hash
    c2.close()


def test_large_message_rejected_before_download(server, tls):
    uid = server.add(b"Subject: big\r\n\r\n" + b"x" * (MAX_RAW_BYTES + 1))
    c = conn(server, tls[1])
    with pytest.raises(EmlTooLarge):
        c.fetch_raw(MessageRef(f"7:{uid}"))
    assert not any("BODY.PEEK" in x for x in server.commands)
    c.close()


def test_plaintext_refused_without_dev_flag():
    with pytest.raises(ConnectorError, match="refusing plaintext"):
        ImapConnector("imap.example.com", "u", password=Secret("p" * 8), port=143, tls=False)
    with pytest.raises(ConnectorError, match="refusing plaintext"):
        build_connector(
            "imap",
            {
                "PHISHGUARD_IMAP_HOST": "h",
                "PHISHGUARD_IMAP_USER": "u",
                "PHISHGUARD_IMAP_PASSWORD": "pppppp",
                "PHISHGUARD_IMAP_TLS": "0",
            },
        )


def test_plaintext_allowed_with_dev_flag_for_local_server():
    s = FakeImapServer()
    try:
        s.add(make_raw("hi"))
        env = {
            "PHISHGUARD_IMAP_HOST": "127.0.0.1",
            "PHISHGUARD_IMAP_PORT": str(s.port),
            "PHISHGUARD_IMAP_USER": s.user,
            "PHISHGUARD_IMAP_PASSWORD": PW,
            "PHISHGUARD_IMAP_TLS": "0",
            "PHISHGUARD_IMAP_ALLOW_PLAINTEXT": "1",
        }
        c = build_connector("imap", env)
        assert len(c.list_recent(5)) == 1
        c.close()
    finally:
        s.close()


def test_tls_certificate_is_verified(server):
    c = ImapConnector("127.0.0.1", server.user, password=Secret(PW), port=server.port)  # system CAs only
    with pytest.raises((ssl.SSLError, OSError)):
        c.list_recent(1)


def test_bad_password_is_a_clean_error_without_the_password(server, tls):
    c = ImapConnector(
        "127.0.0.1", server.user, password=Secret("wrong-password-123"), port=server.port, ssl_context=tls[1]
    )
    with pytest.raises(ConnectorError) as e:
        c.list_recent(1)
    assert "wrong-password-123" not in str(e.value)


def test_xoauth2(tls):
    s = FakeImapServer(tls_files=tls[0], token="ya29.imap-token-abcdefgh")
    try:
        s.add(make_raw("hi"))
        good = ImapConnector(
            "127.0.0.1", s.user, oauth=StaticToken(Secret("ya29.imap-token-abcdefgh")), port=s.port, ssl_context=tls[1]
        )
        assert len(good.list_recent(3)) == 1
        good.close()
        bad = ImapConnector(
            "127.0.0.1", s.user, oauth=StaticToken(Secret("ya29.revoked-token-zzzz")), port=s.port, ssl_context=tls[1]
        )
        with pytest.raises(ConnectorError, match="login"):
            bad.list_recent(1)
        assert not any("ya29" in c for c in s.commands)
    finally:
        s.close()
    assert xoauth2_string("u@x", "t") == b"user=u@x\x01auth=Bearer t\x01\x01"


def test_netease_id_command(tls):
    s = FakeImapServer(tls_files=tls[0], require_id=True)
    try:
        s.add(make_raw("hi"))
        without = ImapConnector("127.0.0.1", s.user, password=Secret(PW), port=s.port, ssl_context=tls[1])
        with pytest.raises(ConnectorError, match="Unsafe Login|cannot open"):
            without.list_recent(1)
        assert PRESETS["163"].send_id
        with_id = ImapConnector("127.0.0.1", s.user, password=Secret(PW), port=s.port, ssl_context=tls[1], send_id=True)
        assert len(with_id.list_recent(1)) == 1
        with_id.close()
    finally:
        s.close()


def test_presets_are_tls_and_documented():
    for name, p in PRESETS.items():
        assert p.port == 993, name
        assert p.notes, name
        assert p.host.startswith("imap.") or p.host == "outlook.office365.com", name
    assert {"icloud", "yahoo", "fastmail", "qq", "163", "zoho"} <= set(PRESETS)


def test_folder_quoting():
    assert quote_mailbox("INBOX") == '"INBOX"'
    assert quote_mailbox('we"ird') == '"we\\"ird"'
    assert _utf7_imap("垃圾邮件") == "&V4NXPpCuTvY-"
    assert _utf7_imap("A&B") == "A&-B"
    with pytest.raises(ValueError):
        quote_mailbox("INBOX\r\nA1 DELETE INBOX")


def test_needs_exactly_one_credential():
    with pytest.raises(ConnectorError):
        ImapConnector("h", "u")
    with pytest.raises(ConnectorError):
        ImapConnector("h", "u", password=Secret("pppppp"), oauth=StaticToken(Secret("tttttt")))
