"""Mailbox remediation: policy, gateway-only execution, provider write calls, banner, worker sink."""

import ssl

import pytest

from phishguard.agent import PhishingAgent
from phishguard.config import Settings
from phishguard.connectors import CheckpointStore, MailboxScanner
from phishguard.connectors import gmail as gm
from phishguard.connectors import graph as gr
from phishguard.connectors.http import HttpClient
from phishguard.connectors.oauth import GoogleRefreshToken, StaticToken
from phishguard.connectors.secrets import Secret
from phishguard.llm import MockLLM
from phishguard.mailbox_guard import GatewaySink, build_gateway
from phishguard.mutating import CaptureChannel, Executor, MFAGateway
from phishguard.mutating.executor import ExecutionGrant
from phishguard.mutating.mailbox import (
    BANNER_HEADER,
    GmailRemediator,
    GraphRemediator,
    ImapRemediator,
    NotSupported,
    TargetMismatch,
    WriteHttpClient,
    _ImapWriteConnection,
    add_banner,
    is_bannered,
    remediation_handlers,
)
from phishguard.mutating.policy import MAX_UNATTENDED_BATCH, ActionType, requires_mfa
from tests.mail_fakes import (
    GMAIL_MODIFY,
    PHISH_RAW_KW,
    FakeGmail,
    FakeGraph,
    FakeImapServer,
    make_raw,
    self_signed_cert,
)
from tests.test_connectors_providers import gmail_conn

KEY = b"banner-key-0123456789abcdef"
P = {"provider": "gmail", "mailbox": "gmail:me/INBOX", "message_id": "18c00001abc"}


# ---------------------------------------------------------------------------------- policy
@pytest.mark.parametrize("action", ["quarantine_email", "mark_spam", "apply_label", "add_warning_banner"])
def test_single_message_remediation_needs_no_mfa(action):
    assert not requires_mfa(ActionType(action), P, "risk 80.0 >= 35.0")


@pytest.mark.parametrize("action", ["delete_email", "release_from_quarantine"])
def test_delete_and_release_always_need_mfa(action):
    assert requires_mfa(ActionType(action), P)


def test_bulk_or_unreadable_batches_need_mfa():
    ids = [f"18c{i:05x}abc" for i in range(MAX_UNATTENDED_BATCH)]
    base = {"provider": "gmail", "mailbox": "gmail:me/INBOX"}
    assert not requires_mfa(ActionType.QUARANTINE_EMAIL, {**base, "message_ids": ids})
    assert requires_mfa(ActionType.QUARANTINE_EMAIL, {**base, "message_ids": ids + ["one-more"]})
    assert requires_mfa(ActionType.QUARANTINE_EMAIL, {**base, "message_ids": "all"})


def test_label_text_with_money_words_still_escalates():
    assert requires_mfa(ActionType.APPLY_LABEL, {**P, "label": "Approved payment"})


# ---------------------------------------------------------------------------------- executor
def test_handlers_only_run_with_a_gateway_grant():
    calls = []
    ex = Executor({ActionType.QUARANTINE_EMAIL: lambda p: calls.append(p) or {"ok": True}})
    with pytest.raises(PermissionError):
        ExecutionGrant(object(), "d")
    with pytest.raises(PermissionError):
        ex.run("not-a-grant", ActionType.QUARANTINE_EMAIL, P)
    assert calls == []
    gw = MFAGateway(executor=ex, channel=CaptureChannel())
    r = gw.submit("quarantine_email", P, "worker", "risk 80 >= 35")
    assert r.status == "executed" and r.result["ok"] and calls == [P]
    r = gw.submit("delete_email", P, "worker")
    assert r.status == "pending_mfa" and len(calls) == 1  # waits for a human
    assert [e["event"] for e in gw.audit.entries()] == ["action_executed", "action_suspended"]
    assert gw.audit.entries()[0]["ok"] is True


def test_handler_failure_is_reported_and_audited_as_not_ok():
    def boom(p):
        raise RuntimeError("provider said no")

    gw = MFAGateway(executor=Executor({ActionType.QUARANTINE_EMAIL: boom}))
    r = gw.submit("quarantine_email", P, "worker")
    assert r.status == "executed" and r.result["ok"] is False and "provider said no" in r.result["outcome"]["error"]
    assert gw.audit.entries()[-1]["ok"] is False


# ---------------------------------------------------------------------------------- Gmail
def gmail_rem(fake, banner=True):
    c = fake.client()
    auth = GoogleRefreshToken(HttpClient(c), "cid", Secret("GOCSPX-w-secret"), Secret(fake.refresh_token))
    http = WriteHttpClient(c, auth=auth, auth_hosts=gm.AUTH_HOSTS, sleep=lambda s: None)
    return GmailRemediator(http, banner_key=Secret(KEY.decode()) if banner else None)


def test_gmail_quarantine_junk_label_delete_release():
    fake = FakeGmail(scope=GMAIL_MODIFY)
    mid = fake.add(make_raw(**PHISH_RAW_KW))
    rem = gmail_rem(fake)
    h = remediation_handlers(rem)
    p = {"provider": "gmail", "mailbox": rem.mailbox_key, "message_id": mid}
    assert h[ActionType.QUARANTINE_EMAIL](p)["ok"]
    qid = fake.labels["PhishGuard/Quarantine"]
    assert fake.messages[mid]["labels"] == {qid}
    h[ActionType.RELEASE_FROM_QUARANTINE](p)
    assert fake.messages[mid]["labels"] == {"INBOX"}
    h[ActionType.APPLY_LABEL]({**p, "label": "PhishGuard/Suspicious"})
    assert fake.labels["PhishGuard/Suspicious"] in fake.messages[mid]["labels"]
    h[ActionType.MARK_SPAM](p)
    assert "SPAM" in fake.messages[mid]["labels"] and "INBOX" not in fake.messages[mid]["labels"]
    h[ActionType.DELETE_EMAIL](p)
    assert fake.messages[mid]["labels"] == {"TRASH"}
    with pytest.raises(ValueError):
        h[ActionType.APPLY_LABEL]({**p, "label": "x\r\nBcc: evil"})


def test_handlers_refuse_a_different_mailbox():
    fake = FakeGmail(scope=GMAIL_MODIFY)
    mid = fake.add(make_raw())
    h = remediation_handlers(gmail_rem(fake))
    for wrong in ({"provider": "graph"}, {"mailbox": "gmail:ceo@corp/INBOX"}):
        with pytest.raises(TargetMismatch):
            h[ActionType.QUARANTINE_EMAIL]({**P, "message_id": mid, **wrong})
    assert fake.modifications == []


def test_gmail_banner_inserts_marked_copy_and_quarantines_original():
    fake = FakeGmail(scope=GMAIL_MODIFY)
    mid = fake.add(make_raw(**PHISH_RAW_KW))
    rem = gmail_rem(fake)
    out = rem.add_warning_banner(mid, 82.4)
    copy = out["bannered_copy"]
    raw = fake.messages[copy]["raw"]
    assert b"PhishGuard warning" in raw and is_bannered(raw, KEY, rem.mailbox_key)
    assert "INBOX" not in fake.messages[mid]["labels"]
    # the copy is scanned again later (new id); bannering it again is a no-op, so no loop
    assert rem.add_warning_banner(copy, 82.4)["noop"] == "already bannered"
    assert gmail_rem(fake, banner=False) and pytest.raises(
        NotSupported, gmail_rem(fake, banner=False).add_warning_banner, mid, 1
    )


def test_banner_header_cannot_be_forged_by_a_sender():
    forged = make_raw(**PHISH_RAW_KW, **{"X_PhishGuard_Banner": "v1; sha=" + "0" * 64 + "; mac=" + "0" * 32})
    assert not is_bannered(forged, KEY, "gmail:me/INBOX")
    out = add_banner(forged, KEY, "gmail:me/INBOX", 90)
    assert out.count(BANNER_HEADER.encode()) == 1  # the forged header was replaced
    assert is_bannered(out, KEY, "gmail:me/INBOX")
    assert not is_bannered(out, KEY, "gmail:someone-else/INBOX")  # bound to the mailbox
    assert not is_bannered(out, b"other-key-xxxxxxxxxxxxxxxx", "gmail:me/INBOX")


def test_banner_on_html_and_multipart_keeps_attachments():
    from email.message import EmailMessage

    m = EmailMessage()
    m["From"] = "x@evil.example"
    m["Subject"] = "Invoice"
    m.set_content("plain body")
    m.add_alternative("<html><body><p>html body</p></body></html>", subtype="html")
    m.add_attachment(b"%PDF-1.4 data", maintype="application", subtype="pdf", filename="inv.pdf")
    out = add_banner(bytes(m), KEY, "mb", 70)
    from email import message_from_bytes, policy

    parsed = message_from_bytes(out, policy=policy.default)
    texts = {p.get_content_type(): p.get_content() for p in parsed.walk() if p.get_content_type().startswith("text/")}
    assert texts["text/plain"].startswith("[PhishGuard warning]")
    assert "<body><div" in texts["text/html"] and "html body" in texts["text/html"]
    att = [p for p in parsed.walk() if p.get_filename() == "inv.pdf"][0]
    assert att.get_content() == b"%PDF-1.4 data"


# ---------------------------------------------------------------------------------- Graph
def test_graph_move_category_and_banner_not_supported():
    fake = FakeGraph(delegated_scope="Mail.ReadWrite offline_access")
    mid = fake.add(make_raw(**PHISH_RAW_KW))
    tok = Secret("graph-write-token-abcdef")
    fake.valid_tokens.add(tok.reveal())
    rem = GraphRemediator(WriteHttpClient(fake.client(), auth=StaticToken(tok), auth_hosts=gr.AUTH_HOSTS))
    h = remediation_handlers(rem)
    p = {"provider": "graph", "mailbox": rem.mailbox_key, "message_id": mid}
    h[ActionType.QUARANTINE_EMAIL](p)
    qid = fake.folders["PhishGuard Quarantine"]
    assert fake.messages[mid]["folder"] == qid
    h[ActionType.QUARANTINE_EMAIL](p)  # folder looked up once, reused
    assert sum(1 for r in fake.requests if r.method == "POST" and r.url.path.endswith("/mailFolders")) == 1
    h[ActionType.MARK_SPAM](p)
    assert fake.messages[mid]["folder"] == "junkemail"
    h[ActionType.APPLY_LABEL]({**p, "label": "PhishGuard"})
    h[ActionType.APPLY_LABEL]({**p, "label": "PhishGuard"})
    assert fake.messages[mid]["categories"] == ["PhishGuard"] and len(fake.patches) == 1
    with pytest.raises(NotSupported, match="transport rule"):
        rem.add_warning_banner(mid, 90)
    assert all(
        r.headers.get("prefer") == 'IdType="ImmutableId"' for r in fake.requests if r.url.host == "graph.microsoft.com"
    )


# ---------------------------------------------------------------------------------- IMAP
@pytest.fixture
def imap_env(tmp_path):
    cert, key = self_signed_cert(tmp_path)
    ctx = ssl.create_default_context(cafile=cert)
    servers = []

    def make(**kw):
        s = FakeImapServer(tls_files=(cert, key), **kw)
        servers.append(s)
        return s

    yield make, ctx
    for s in servers:
        s.close()


def imap_rem(server, ctx):
    conn = _ImapWriteConnection(
        "127.0.0.1", server.user, password=Secret(server.password), port=server.port, ssl_context=ctx
    )
    return ImapRemediator(conn, banner_key=Secret(KEY.decode()))


def test_imap_move_with_move_capability(imap_env):
    make, ctx = imap_env
    s = make()
    uid = s.add(make_raw(**PHISH_RAW_KW))
    rem = imap_rem(s, ctx)
    out = rem.quarantine(f"7:{uid}")
    assert out["ok"] and uid not in s.folders["INBOX"]["msgs"]
    assert len(s.folders["PhishGuard-Quarantine"]["msgs"]) == 1
    assert any("CREATE" in c for c in s.commands) and any("UID MOVE" in c for c in s.commands)
    rem.close()


def test_imap_copy_expunge_only_this_uid_with_uidplus(imap_env):
    make, ctx = imap_env
    s = make(caps=("IMAP4rev1", "UIDPLUS"))
    keep = s.add(make_raw("user flagged this"), flags={"\\Deleted"})
    uid = s.add(make_raw(**PHISH_RAW_KW))
    rem = imap_rem(s, ctx)
    rem.mark_spam(f"7:{uid}")
    assert uid not in s.folders["INBOX"]["msgs"] and keep in s.folders["INBOX"]["msgs"]
    assert any(c.endswith(f"UID EXPUNGE {uid}") for c in s.commands)
    rem.close()


def test_imap_never_plain_expunges_without_uidplus(imap_env):
    make, ctx = imap_env
    s = make(caps=("IMAP4rev1",))
    keep = s.add(make_raw("user flagged this"), flags={"\\Deleted"})
    uid = s.add(make_raw(**PHISH_RAW_KW))
    rem = imap_rem(s, ctx)
    out = rem.delete(f"7:{uid}")
    assert "not expunged" in out["note"]
    assert keep in s.folders["INBOX"]["msgs"] and "\\Deleted" in s.folders["INBOX"]["msgs"][uid]["flags"]
    assert not any("EXPUNGE" in c for c in s.commands)
    rem.close()


def test_imap_label_keyword_and_banner(imap_env):
    make, ctx = imap_env
    s = make()
    uid = s.add(make_raw(**PHISH_RAW_KW))
    rem = imap_rem(s, ctx)
    rem.apply_label(f"7:{uid}", "PhishGuard/Suspicious")
    assert "$PhishGuardSuspicious" in s.folders["INBOX"]["msgs"][uid]["flags"]
    rem.add_warning_banner(f"7:{uid}", 75)
    inbox = s.folders["INBOX"]["msgs"]
    assert uid not in inbox and len(inbox) == 1
    assert is_bannered(next(iter(inbox.values()))["raw"], KEY, rem.mailbox_key)
    rem.close()


# ---------------------------------------------------------------------------------- worker sink, end to end
def test_mailbox_guard_quarantines_flagged_mail_only(tmp_path):
    import json
    import os

    fake = FakeGmail(scope=GMAIL_MODIFY)
    cfile = tmp_path / "client.json"
    cfile.write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "GOCSPX-zzzzzzzzzz"}}))
    os.chmod(cfile, 0o600)
    env = {
        "PHISHGUARD_GMAIL_CLIENT_FILE": str(cfile),
        "PHISHGUARD_TOKEN_FILE": str(tmp_path / "read.json"),
        "PHISHGUARD_WRITE_TOKEN_FILE": str(tmp_path / "write.json"),
    }
    from phishguard.connectors.config import token_store
    from phishguard.connectors.oauth import OAuthError

    settings = Settings(llm_mode="mock")
    with pytest.raises(OAuthError):  # write access is opt-in: no write token, no remediation
        build_gateway("gmail", env, settings, client=fake.client())
    token_store(env, write=True).put("gmail:write", {"refresh_token": fake.refresh_token})
    gw = build_gateway("gmail", env, settings, client=fake.client())
    sink = GatewaySink(gw, ["label", "quarantine"])
    scanner = MailboxScanner(
        gmail_conn(fake, allow_overprivileged=True),
        PhishingAgent(MockLLM(), settings),
        CheckpointStore(":memory:"),
        sink=sink,
    )
    scanner.poll_once()
    bad = fake.add(make_raw(**PHISH_RAW_KW))
    ok = fake.add(make_raw("Team lunch", body="Pizza at noon in room 4."))
    scanner.poll_once()
    assert "INBOX" not in fake.messages[bad]["labels"] and fake.messages[ok]["labels"] == {"INBOX"}
    assert [r["status"] for r in sink.submitted] == ["executed", "executed"]
    scanner.poll_once()
    assert len(sink.submitted) == 2  # idempotent: no second action on the next round
    events = [e["event"] for e in gw.audit.entries()]
    assert events == ["action_executed", "action_executed"] and gw.audit.verify_chain()
