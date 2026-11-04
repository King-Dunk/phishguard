"""Mailbox remediation (mutating side), policy rules, worker, CLIs, and secrets never leaking."""

import email
import email.policy
import json
import logging

import httpx
import pytest

from phishguard.config import Settings
from phishguard.connectors import CheckpointStore
from phishguard.connectors import factory as F
from phishguard.connectors.auth import StaticToken
from phishguard.connectors.gmail import API_HOST, GmailConnector
from phishguard.connectors.graph import GRAPH_HOST
from phishguard.connectors.http import RetryingClient
from phishguard.connectors.imap import ImapConnector
from phishguard.connectors.secrets import REPO_ROOT
from phishguard.mutating import AuditLog, CaptureChannel, MFAGateway
from phishguard.mutating.executor import Executor
from phishguard.mutating.policy import MAILBOX_BULK_LIMIT, ActionType, requires_mfa
from phishguard.mutating.remediation import (
    GmailWriter,
    GraphWriter,
    ImapWriter,
    NotSupported,
    add_banner,
    build_writer,
    handlers,
)
from phishguard.worker import MailboxWorker
from tests.fakes import TOKEN, FakeGmail, FakeGraph, FakeImapServer, ImapState

FIX = REPO_ROOT / "tests" / "fixtures"
PHISH = (FIX / "phish_bec_auth_fail.eml").read_bytes()
BENIGN = (FIX / "benign_internal_plain.eml").read_bytes()
HTML = (FIX / "phish_link_text_mismatch.eml").read_bytes()


# ================================================================ policy
Q, L, B, D, R = (
    ActionType.MAILBOX_QUARANTINE,
    ActionType.MAILBOX_LABEL,
    ActionType.MAILBOX_BANNER,
    ActionType.MAILBOX_DELETE,
    ActionType.MAILBOX_RESTORE,
)


def test_single_message_quarantine_label_banner_need_no_mfa():
    for a in (Q, L, B):
        assert not requires_mfa(
            a, {"provider": "gmail", "mailbox": "work", "message_ids": ["18c2f0a1"], "verdict_risk": 88.1}
        )


def test_delete_and_restore_always_need_mfa():
    for a in (D, R):
        assert requires_mfa(a, {"mailbox": "work", "message_ids": ["x1"]})


def test_bulk_and_malformed_ids_need_mfa():
    ids = [f"id{i}" for i in range(MAILBOX_BULK_LIMIT + 1)]
    assert requires_mfa(Q, {"mailbox": "w", "message_ids": ids})
    assert not requires_mfa(Q, {"mailbox": "w", "message_ids": ids[:MAILBOX_BULK_LIMIT]})
    for bad in ([], "x1", None, ["a b"], ["x" * 600], [{"nested": "id"}]):
        assert requires_mfa(Q, {"mailbox": "w", "message_ids": bad}), bad


def test_opaque_ids_dont_trip_content_escalation_but_other_params_do():
    graph_id = "AAMkAGI2THVSAAA=wireBANKswift+/iban"  # base64-ish ids can contain money words by chance
    assert not requires_mfa(Q, {"mailbox": "w", "message_ids": [graph_id]})
    assert requires_mfa(L, {"mailbox": "w", "message_ids": ["x1"], "label": "approve invoice payment"})
    assert requires_mfa(Q, {"mailbox": "w", "message_ids": ["x1"], "bank": "x"})


# ================================================================ executor handlers
def _grant():
    from phishguard.mutating.executor import _issue_grant

    return _issue_grant("d")


def test_executor_reports_handler_failure_honestly():
    def boom(p):
        raise RuntimeError("provider said no for token " + TOKEN)

    StaticToken(TOKEN)  # registers it for redaction
    ex = Executor({Q: boom, L: lambda p: {"labeled": 1}})
    r = ex.run(_grant(), Q, {"message_ids": ["x"]})
    assert r["ok"] is False and TOKEN not in r["error"] and "***" in r["error"]
    assert ex.run(_grant(), L, {})["labeled"] == 1
    assert ex.run(_grant(), ActionType.TRANSFER_FUNDS, {})["ok"] is True  # simulated as before
    with pytest.raises(PermissionError):
        ex.run(None, Q, {})


# ================================================================ banner
def test_banner_text_and_html_and_attachments_untouched():
    out = email.message_from_bytes(add_banner(HTML, 91.2), policy=email.policy.default)
    assert out["X-PhishGuard-Verdict"] == "phishing; risk=91.2"
    body = out.get_body(("html",)).get_content()
    assert "WARNING from PhishGuard" in body and "risk 91.2" in body
    mixed = (FIX / "phish_iso_attachment.eml").read_bytes()
    m2 = email.message_from_bytes(add_banner(mixed, 80), policy=email.policy.default)
    assert m2.get_body(("plain",)).get_content().startswith("[WARNING from PhishGuard")
    att = [p for p in m2.iter_attachments()]
    assert att and att[0].get_filename() == "label_7731.iso" and att[0].get_payload(decode=True) == b"CD001 fake iso"


# ================================================================ writers
def gm():
    g = FakeGmail()
    g.add("p1", PHISH)
    g.add("b1", BENIGN)
    return g, GmailWriter(RetryingClient(g.client(), StaticToken(TOKEN), [API_HOST]))


def test_gmail_writer_actions():
    g, w = gm()
    w.quarantine(["p1"])
    qid = g.labels["PhishGuard/Quarantine"]
    assert g.msgs["p1"]["labels"] == {qid}
    w.label(["b1"], "PhishGuard/Suspicious")
    assert g.labels["PhishGuard/Suspicious"] in g.msgs["b1"]["labels"]
    w.restore(["p1"])
    assert "INBOX" in g.msgs["p1"]["labels"] and qid not in g.msgs["p1"]["labels"]
    w.delete(["b1"])
    assert g.msgs["b1"]["labels"] == {"TRASH"}


def test_gmail_banner_inserts_annotated_copy_and_quarantines_original():
    g, w = gm()
    r = w.banner(["p1"], 95)
    assert r["bannered"] == 1 and len(g.inserted) == 1
    assert b"WARNING from PhishGuard" in g.inserted[0] and b"X-PhishGuard-Verdict" in g.inserted[0]
    assert "INBOX" not in g.msgs["p1"]["labels"] and "INBOX" in g.msgs[r["copies"][0]]["labels"]


def test_graph_writer_actions_and_banner_not_supported():
    g = FakeGraph()
    g.add("m1", PHISH)
    g.add("m2", BENIGN)
    w = GraphWriter(RetryingClient(g.client(), StaticToken(TOKEN), [GRAPH_HOST]))
    w.quarantine(["m1"])
    assert g.msgs["m1"]["folder"] == "junkemail"
    w.label(["m2"], "PhishGuard: suspected phishing")
    w.label(["m2"], "PhishGuard: suspected phishing")  # idempotent
    assert g.msgs["m2"]["categories"] == ["PhishGuard: suspected phishing"]
    w.restore(["m1"])
    w.delete(["m2"])
    assert g.msgs["m1"]["folder"] == "inbox" and g.msgs["m2"]["folder"] == "deleteditems"
    with pytest.raises(NotSupported):
        w.banner(["m1"], 90)
    ex = Executor(handlers({"o365": w}))
    assert ex.run(_grant(), B, {"mailbox": "o365", "message_ids": ["m1"]})["ok"] is False


def test_imap_writer_moves_labels_banners():
    st = ImapState()
    u1, u2 = st.add(PHISH), st.add(BENIGN)
    with FakeImapServer(st) as srv:
        c = ImapConnector(
            "ic", "127.0.0.1", st.user, password=st.password, port=srv.port, tls="none", allow_plaintext=True
        )
        w = ImapWriter(c)
        w.label([f"42:{u2}"], "PhishGuard suspected")
        assert "$PhishGuardsuspected" in st.folders["INBOX"][1][2]
        w.banner([f"42:{u1}"], 90)
        assert len(st.folders["Junk"]) == 1 and st.folders["Junk"][0][1] == PHISH
        assert b"WARNING from PhishGuard" in st.folders["INBOX"][-1][1]
        junk_uid = st.folders["Junk"][0][0]
        w.restore([f"42:{junk_uid}"])
        assert st.folders["Junk"] == [] and any(raw == PHISH for _, raw, _ in st.folders["INBOX"])
        w.delete([f"42:{st.folders['INBOX'][0][0]}"])
        assert len(st.folders["Trash"]) == 1
    assert "SELECT" in st.commands  # writes use their own read-write session


def test_unknown_mailbox_is_not_supported():
    ex = Executor(handlers({}))
    r = ex.run(_grant(), Q, {"mailbox": "nope", "message_ids": ["x"]})
    assert r["ok"] is False and "not enabled" in r["error"]


# ================================================================ config: separate read / write credentials
def test_writer_only_when_enabled_and_needs_separate_auth():
    m = {"name": "w", "provider": "gmail", "auth": {"client_file": "/x", "token_file": "/y"}}
    assert build_writer(m) is None
    assert build_writer({**m, "remediation": {"enabled": False}}) is None
    with pytest.raises(ValueError, match="write credentials"):
        build_writer({**m, "remediation": {"enabled": True}})
    assert F.scopes_for("gmail", False, "oauth") == ("https://www.googleapis.com/auth/gmail.readonly",)
    assert F.scopes_for("gmail", True, "oauth") == ("https://www.googleapis.com/auth/gmail.modify",)
    assert (
        "Mail.Read" in F.scopes_for("graph", False, "delegated")[0]
        and "Mail.ReadWrite" in F.scopes_for("graph", True, "delegated")[0]
    )


def test_config_rejects_inline_secrets_and_bad_entries(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("mailboxes:\n  - {name: a, provider: imap, auth: {password: hunter2}}\n")
    with pytest.raises(F.ConfigError, match="password_env"):
        F.load_config(p)
    p.write_text("mailboxes:\n  - {name: a, provider: pop3}\n")
    with pytest.raises(F.ConfigError):
        F.load_config(p)
    p.write_text("mailboxes:\n  - {name: a, provider: imap}\n  - {name: a, provider: imap}\n")
    with pytest.raises(F.ConfigError, match="unique"):
        F.load_config(p)


def test_graph_app_only_needs_a_user():
    with pytest.raises(F.ConfigError, match="UPN"):
        F.build_connector(
            {
                "name": "g",
                "provider": "graph",
                "auth": {"type": "client_credentials", "client_id": "c", "client_secret_env": "X"},
            }
        )


def test_imap_preset_resolution(monkeypatch):
    monkeypatch.setenv("PG_T_PW", "app-pass-123456")
    c = F.build_connector(
        {"name": "n", "provider": "imap", "preset": "163", "username": "u@163.com", "auth": {"password_env": "PG_T_PW"}}
    )
    assert (c.host, c.port, c.send_id, c.tls) == ("imap.163.com", 993, True, "implicit")
    with pytest.raises(F.ConfigError, match="preset"):
        F.build_connector({"name": "n", "provider": "imap", "username": "u", "auth": {"password_env": "PG_T_PW"}})


# ================================================================ worker
def worker_for(g: FakeGmail, name="work", rem=None, settings=None):
    s = settings or Settings(executives=("David Chen",))
    m = {
        "name": name,
        "provider": "gmail",
        "remediation": rem or {"enabled": True, "action": "quarantine", "min_risk": 50},
    }
    conn = GmailConnector(RetryingClient(g.client(), StaticToken(TOKEN), [API_HOST]), name)
    writer = GmailWriter(RetryingClient(g.client(), StaticToken(TOKEN), [API_HOST]))
    gw = MFAGateway(executor=Executor(handlers({name: writer})), audit=AuditLog(), channel=CaptureChannel())
    return MailboxWorker({"mailboxes": [m]}, s, gw, CheckpointStore(), connectors={name: conn})


def test_worker_scans_and_quarantines_only_phishing_once():
    g = FakeGmail()
    for i, p in enumerate(sorted(FIX.glob("*.eml"))):
        g.add(f"m{i}", p.read_bytes())
    w = worker_for(g)
    run = w.run_once()[0]
    flagged = {v.provider_id for v in run.verdicts if v.is_phishing and v.risk >= 50}
    assert flagged and {a["provider_id"] for a in run.actions} == flagged
    assert all(a["status"] == "executed" and a["ok"] for a in run.actions)
    q = g.labels["PhishGuard/Quarantine"]
    assert {m for m, v in g.msgs.items() if q in v["labels"]} == flagged
    assert all("INBOX" in g.msgs[f"m{i}"]["labels"] for i in range(3))  # benign_* untouched
    again = w.run_once()[0]
    assert again.verdicts == [] and again.actions == []
    events = [e["event"] for e in w.gateway.audit.entries()]
    assert events.count("remediation_result") == len(flagged) and w.gateway.audit.verify_chain()


def test_worker_dry_run_and_disabled_remediation_change_nothing():
    for kw in ({"rem": {"enabled": False}}, {}):
        g = FakeGmail()
        g.add("p", PHISH)
        w = worker_for(g, **kw)
        run = w.run_once(dry_run=not kw)[0]
        assert run.verdicts and run.actions == [] and g.methods() == {"GET"}


def test_worker_content_escalation_leaves_action_pending():
    g = FakeGmail()
    g.add("p", PHISH)
    w = worker_for(g, name="payroll pay box")  # mailbox name contains a money word
    run = w.run_once()[0]
    assert run.actions[0]["status"] == "pending_mfa" and "PhishGuard/Quarantine" not in g.labels


def test_worker_pauses_rate_limited_mailbox():
    g = FakeGmail()
    g.add("p", PHISH)
    g.forced = [httpx.Response(429, headers={"Retry-After": "900"})]
    w = worker_for(g)
    w.connectors["work"].http.max_delay = 60
    run = w.run_once()[0]
    assert run.retry_after == 900 and "paused" not in (run.error or "")
    assert w.run_once()[0].error == "rate limited; paused"


def test_worker_triggers_scan_early():
    import threading

    g = FakeGmail()
    g.add("p", PHISH)
    w = worker_for(g, rem={"enabled": False})
    stop = threading.Event()
    w.store.add_trigger("work", "graph")
    calls = []
    w.run_once = lambda names=None, dry_run=False: calls.append(names) or []  # type: ignore[method-assign]
    t = threading.Thread(target=w.loop, args=(3600, stop), kwargs={"tick": 0.01})
    t.start()
    import time

    time.sleep(0.2)
    stop.set()
    t.join(2)
    assert calls[0] is None and ["work"] in calls  # full pass, then the triggered mailbox


# ================================================================ mailbox_action CLI (human + MFA)
def test_mailbox_action_restore_needs_code(capsys):
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import mailbox_action

    g = FakeGmail()
    g.add("p", PHISH, labels=("Label_9",))
    w = worker_for(g)
    w.gateway.channel = ch = CaptureChannel()
    codes = iter(["000000x"])

    def ask(prompt):
        return next(codes, None) or next(iter(ch.codes.values()))

    rc = mailbox_action.main(["--mailbox", "work", "--as", "alice", "restore", "--ids", "p"], ask=ask, worker=w)
    out = capsys.readouterr().out
    assert rc == 0 and "MFA required" in out and "rejected" in out and "INBOX" in g.msgs["p"]["labels"]
    rc = mailbox_action.main(["--mailbox", "work", "--as", "alice", "quarantine", "--ids", "p"], ask=ask, worker=w)
    assert rc == 0 and "MFA required" not in capsys.readouterr().out


# ================================================================ secrets never leak
def oauth_and_gmail_transport(g: FakeGmail):
    def h(r: httpx.Request):
        if r.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": TOKEN, "expires_in": 3600})
        return g.handle(r)

    return httpx.Client(transport=httpx.MockTransport(h))


def test_no_secret_in_logs_audit_or_cli_output(tmp_path, monkeypatch, caplog, capsys):
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import scan_mailbox

    refresh, csecret = "1//0g-refresh-token-SECRET-777", "GOCSPX-client-SECRET-888"
    client = tmp_path / "client.json"
    client.write_text(
        json.dumps({"installed": {"client_id": "cid.apps.googleusercontent.com", "client_secret": csecret}})
    )
    client.chmod(0o600)
    tok = tmp_path / "tok.json"
    from phishguard.connectors.secrets import TokenStore

    TokenStore(tok).save({"refresh_token": refresh})
    g = FakeGmail()
    for i, p in enumerate(sorted(FIX.glob("*.eml"))):
        g.add(f"m{i}", p.read_bytes())
    monkeypatch.setattr(F, "http_client", lambda: oauth_and_gmail_transport(g))
    with caplog.at_level(logging.DEBUG):
        rc = scan_mailbox.main(
            ["--provider", "gmail", "--client-file", str(client), "--token-file", str(tok), "--last", "20", "--json"]
        )
        # and through the worker + audit, with a provider error that echoes the token
        w = worker_for(g)
        logging.getLogger("phishguard.connectors").error("upstream said: Bearer %s / %s / %s", TOKEN, refresh, csecret)
        w.run_once()
    out = capsys.readouterr()
    assert rc == 0 and json.loads(out.out)["verdicts"]
    blob = out.out + out.err + caplog.text + json.dumps(w.gateway.audit.entries())
    for secret in (refresh, csecret, TOKEN):
        assert secret not in blob, secret


def test_cli_error_messages_are_redacted(tmp_path, monkeypatch, capsys):
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import scan_mailbox

    monkeypatch.setenv("PG_LEAKY", "imap-app-password-SECRET-999")
    rc = scan_mailbox.main(
        [
            "--provider",
            "imap",
            "--host",
            "127.0.0.1",
            "--port",
            "1",
            "--username",
            "u",
            "--password-env",
            "PG_LEAKY",
            "--last",
            "1",
        ]
    )
    err = capsys.readouterr()
    assert rc == 2 and "cannot connect" in err.err
    assert "imap-app-password-SECRET-999" not in err.out + err.err
