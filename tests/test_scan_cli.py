"""scan_mailbox.py: Graph subscribe / Gmail watch flags through the CLI (fakes, no network)."""

import sys

import httpx

from phishguard.connectors import factory as F
from phishguard.connectors.secrets import REPO_ROOT, TokenStore
from tests.fakes import TOKEN, FakeGmail, FakeGraph

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import scan_mailbox  # noqa: E402


def _transport(fake):
    def h(r):
        if r.url.host in ("login.microsoftonline.com", "oauth2.googleapis.com"):
            return httpx.Response(200, json={"access_token": TOKEN, "expires_in": 3600})
        return fake.handle(r)

    return lambda: httpx.Client(transport=httpx.MockTransport(h))


def test_graph_subscribe_flag(tmp_path, monkeypatch, capsys):
    g = FakeGraph()
    monkeypatch.setattr(F, "http_client", _transport(g))
    tok = tmp_path / "t.json"
    TokenStore(tok).save({"refresh_token": "rt-graph-123456"})
    monkeypatch.setenv("PG_CS", "client-state-abcdef")
    rc = scan_mailbox.main(
        [
            "--provider",
            "graph",
            "--client-id",
            "cid",
            "--token-file",
            str(tok),
            "--graph-subscribe",
            "https://pg.example.com/webhooks/graph",
            "--client-state-env",
            "PG_CS",
        ]
    )
    assert rc == 0 and g.subscriptions[0]["clientState"] == "client-state-abcdef"
    assert "client-state-abcdef" not in capsys.readouterr().out


def test_gmail_watch_flag(tmp_path, monkeypatch, capsys):
    import json

    g = FakeGmail()
    monkeypatch.setattr(F, "http_client", _transport(g))
    client = tmp_path / "c.json"
    client.write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "cs-123456"}}))
    client.chmod(0o600)
    tok = tmp_path / "t.json"
    TokenStore(tok).save({"refresh_token": "rt-gmail-123456"})
    rc = scan_mailbox.main(
        [
            "--provider",
            "gmail",
            "--client-file",
            str(client),
            "--token-file",
            str(tok),
            "--gmail-watch",
            "projects/p/topics/t",
        ]
    )
    assert rc == 0 and "Gmail watch active" in capsys.readouterr().out


def test_redacted_table_output(tmp_path, monkeypatch, capsys):
    import json

    g = FakeGmail()
    for i, p in enumerate(sorted((REPO_ROOT / "tests" / "fixtures").glob("*.eml"))):
        g.add(f"m{i}", p.read_bytes())
    monkeypatch.setattr(F, "http_client", _transport(g))
    client = tmp_path / "c.json"
    client.write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "cs-123456"}}))
    client.chmod(0o600)
    tok = tmp_path / "t.json"
    TokenStore(tok).save({"refresh_token": "rt-gmail-123456"})
    args = ["--provider", "gmail", "--client-file", str(client), "--token-file", str(tok), "--last", "20"]
    assert scan_mailbox.main(args + ["--redact"]) == 0
    out = capsys.readouterr().out
    assert "PHISH" in out and "10 scanned" in out and "Urgent wire" not in out
    assert scan_mailbox.main(args) == 0
    assert "Urgent wire today" in capsys.readouterr().out  # subjects shown unless --redact


def test_example_config_loads_and_holds_no_secrets():
    cfg = F.load_config(REPO_ROOT / "examples" / "mailboxes.example.yaml")
    assert {m["provider"] for m in cfg["mailboxes"]} == {"gmail", "graph", "imap"}
    text = (REPO_ROOT / "examples" / "mailboxes.example.yaml").read_text()
    assert "password:" not in text and "client_secret:" not in text and "refresh_token" not in text
