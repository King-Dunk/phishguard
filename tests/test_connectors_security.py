"""Connector security: read-only isolation, read-only verbs, secret handling, webhook validation."""

import ast
import base64
import io
import json
import logging
import os
import pathlib
import subprocess
import sys
import textwrap
import time

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import phishguard
from phishguard.agent import PhishingAgent
from phishguard.config import Settings
from phishguard.connectors import CheckpointStore, MailboxScanner
from phishguard.connectors.http import HttpClient
from phishguard.connectors.secrets import (
    REPO_ROOT,
    RedactingFilter,
    Secret,
    SecretError,
    TokenStore,
    check_secret_path,
    read_secret_file,
    redact,
)
from phishguard.connectors.webhooks import JwksCache, make_router
from phishguard.connectors.worker import run
from phishguard.llm import MockLLM
from tests.mail_fakes import PHISH_RAW_KW, FakeGmail, FakeGraph, make_raw
from tests.test_connectors_providers import gmail_conn, graph_conn
from tests.test_isolation import _scan

ROOT = pathlib.Path(phishguard.__file__).parent
CONNECTORS = sorted((ROOT / "connectors").rglob("*.py"))


# ---------------------------------------------------------------------------------- isolation
def test_connector_source_never_imports_mutating_or_api():
    assert CONNECTORS and _scan(CONNECTORS) == []


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)], capture_output=True, text=True, cwd=ROOT.parent
    )


def test_connector_runtime_import_closure_excludes_mutating():
    r = _run("""
        import sys
        import phishguard.connectors, phishguard.connectors.worker, phishguard.connectors.webhooks
        import phishguard.connectors.config, phishguard.connectors.gmail, phishguard.connectors.graph
        import phishguard.connectors.imap
        bad = [m for m in sys.modules if m.startswith('phishguard.mutating') or m == 'phishguard.api']
        print(bad); sys.exit(1 if bad else 0)
    """)
    assert r.returncode == 0, r.stdout + r.stderr


def test_scanning_works_with_mutating_import_blocked():
    r = _run("""
        import sys, importlib.abc
        class Block(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path, target=None):
                if name.startswith('phishguard.mutating') or name == 'phishguard.api':
                    raise ImportError('blocked: ' + name)
        sys.meta_path.insert(0, Block())
        from tests.mail_fakes import FakeGmail, make_raw, PHISH_RAW_KW
        from tests.test_connectors_providers import gmail_conn
        from phishguard.connectors import MailboxScanner, CheckpointStore
        from phishguard.agent import PhishingAgent
        from phishguard.config import Settings
        from phishguard.llm import MockLLM
        fake = FakeGmail(); fake.add(make_raw(**PHISH_RAW_KW))
        s = MailboxScanner(gmail_conn(fake), PhishingAgent(MockLLM(), Settings()), CheckpointStore(':memory:'))
        print([v.is_phishing for v in s.scan_recent(5)])
    """)
    assert r.returncode == 0 and "[True]" in r.stdout, r.stdout + r.stderr


HTTP_WRITE = {"patch", "put", "delete", "send_json", "request", "stream"}
IMAP_WRITE = {"store", "copy", "move", "expunge", "append", "create", "delete", "rename", "subscribe", "setacl"}
HTTP_RECEIVERS = {"self.http", "http", "self._client", "client", "tok_http", "self._http"}
IMAP_RECEIVERS = {"conn", "self._conn", "self._c()"}


def test_connector_source_has_no_write_verbs():
    """AST: no PATCH/PUT/DELETE calls, no IMAP STORE/COPY/MOVE/EXPUNGE/APPEND, select() only read-only."""
    bad = []
    for f in CONNECTORS:
        tree = ast.parse(f.read_text())
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                name = n.func.attr.lower()
                recv = ast.unparse(n.func.value)
                if (recv in HTTP_RECEIVERS and name in HTTP_WRITE) or (recv in IMAP_RECEIVERS and name in IMAP_WRITE):
                    bad.append((f.name, n.lineno, f"{recv}.{name}"))
                if name == "select":
                    ro = [k for k in n.keywords if k.arg == "readonly"]
                    if not (ro and isinstance(ro[0].value, ast.Constant) and ro[0].value.value is True):
                        bad.append((f.name, n.lineno, "select without readonly=True"))
                if (
                    name == "_send"
                    and n.args
                    and isinstance(n.args[0], ast.Constant)
                    and n.args[0].value not in ("GET", "POST")
                ):
                    bad.append((f.name, n.lineno, n.args[0].value))
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                if n.value.upper() in ("STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "+FLAGS", "+FLAGS.SILENT"):
                    bad.append((f.name, n.lineno, n.value))
    assert bad == []


ALLOWED_POSTS = {
    ("oauth2.googleapis.com", "/token"),
    ("gmail.googleapis.com", "/gmail/v1/users/me/watch"),
    ("graph.microsoft.com", "/v1.0/subscriptions"),
}


def test_read_connectors_only_issue_get_at_runtime(tmp_path):
    """Every request a full scan makes is a GET, except token endpoints and read-scoped subscriptions."""
    agent = PhishingAgent(MockLLM(), Settings())
    fake = FakeGmail()
    gc = gmail_conn(fake)
    s = MailboxScanner(gc, agent, CheckpointStore(":memory:"), backfill=2)
    fake.add(make_raw("a"))
    s.poll_once()
    fake.add(make_raw(**PHISH_RAW_KW))
    s.poll_once()
    s.scan_recent(5)
    gc.watch("projects/my-proj/topics/phishguard")
    gfake = FakeGraph()
    gconn, _ = graph_conn(gfake, tmp_path)
    s2 = MailboxScanner(gconn, agent, CheckpointStore(":memory:"), backfill=2)
    gfake.add(make_raw("b"))
    s2.poll_once()
    gfake.add(make_raw(**PHISH_RAW_KW))
    s2.poll_once()
    gconn.subscribe("https://hook.example/webhooks/graph", "c" * 32)
    reqs = fake.requests + gfake.requests
    assert len(reqs) > 10
    for r in reqs:
        if r.method != "GET":
            host = r.url.host
            path = r.url.path
            ok = (host, path) in ALLOWED_POSTS or (host == "login.microsoftonline.com" and path.endswith("/token"))
            assert r.method == "POST" and ok, (r.method, str(r.url))
    assert not fake.modifications and not gfake.moves and not gfake.patches


# ---------------------------------------------------------------------------------- secrets
def test_secret_never_prints():
    s = Secret("hunter2-super-secret")
    assert "hunter2" not in repr(s) + str(s) + f"{s}" + f"{[s]}"
    with pytest.raises(TypeError):
        import pickle

        pickle.dumps(s)


def test_redaction_patterns():
    Secret("registered-value-123")
    text = (
        "Authorization: Bearer ya29.a0AfH6SMBxxxxxxxx refresh_token=1//0gAbCdEfGhIjKlMn "
        '{"access_token": "eyJhbGciOi.eyJzdWIiOiIx.c2ln", "client_secret":"GOCSPX-abcdef"} '
        "registered-value-123 user=a\x01auth=Bearer tok123456\x01 ?code=4/0AX4XfWh&state=1 password=hunter22"
    )
    out = redact(text)
    for leak in (
        "ya29.a0",
        "1//0gAb",
        "eyJhbGci",
        "GOCSPX-abcdef",
        "registered-value-123",
        "tok123456",
        "4/0AX4XfWh",
        "hunter22",
    ):
        assert leak not in out, leak
    assert redact("error code: invalid_grant (HTTP 400)") == "error code: invalid_grant (HTTP 400)"


def test_log_filter_scrubs_messages_args_and_tracebacks():
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.addFilter(RedactingFilter())
    log = logging.getLogger("phishguard.test.redact")
    log.addHandler(h)
    log.setLevel(logging.INFO)
    sec = Secret("very-secret-refresh-token-xyz")
    try:
        log.info("token %s", sec.reveal())
        try:
            raise RuntimeError("failed with " + sec.reveal())
        except RuntimeError:
            log.exception("boom")
    finally:
        log.removeHandler(h)
    assert "very-secret-refresh-token-xyz" not in buf.getvalue() and "[REDACTED]" in buf.getvalue()


def test_secret_files_inside_repo_or_world_readable_are_refused(tmp_path, monkeypatch):
    with pytest.raises(SecretError, match="inside the repository"):
        check_secret_path(REPO_ROOT / "client_secret.json", must_exist=False)
    with pytest.raises(SecretError, match="inside the repository"):
        TokenStore(REPO_ROOT / "tokens.json")
    f = tmp_path / "pw"
    f.write_text("app-password\n")
    os.chmod(f, 0o644)
    with pytest.raises(SecretError, match="chmod 600"):
        read_secret_file(f)
    os.chmod(f, 0o600)
    assert read_secret_file(f).reveal() == "app-password"
    monkeypatch.setenv("PHISHGUARD_ALLOW_INSECURE_SECRET_PERMS", "1")
    os.chmod(f, 0o644)
    assert read_secret_file(f).reveal() == "app-password"


def test_token_store_is_0600_and_atomic(tmp_path):
    st = TokenStore(tmp_path / "d" / "t.json")
    st.put("a", {"refresh_token": "rt-111111"})
    st.put("b", {"refresh_token": "rt-222222"})
    assert st.get("a")["refresh_token"] == "rt-111111"
    assert oct(os.stat(st.path).st_mode & 0o777) == "0o600"
    assert not [p for p in st.path.parent.iterdir() if p.name.startswith(".tok-")]


def test_secrets_never_reach_logs_output_or_state(tmp_path, caplog):
    """End to end: run the worker with real credential objects and grep everything it produced."""
    caplog.set_level(logging.DEBUG)
    fake = FakeGmail()
    conn = gmail_conn(fake)
    state_path = tmp_path / "state.db"
    s = MailboxScanner(conn, PhishingAgent(MockLLM(), Settings()), CheckpointStore(str(state_path)), backfill=5)
    fake.add(make_raw(**PHISH_RAW_KW))
    fake.add(make_raw("hello"))
    fake.queue = [httpx.Response(429, headers={"Retry-After": "0"})]
    out = io.StringIO()
    run(s, 10, out=out, max_rounds=1)
    fake.valid_tokens.clear()  # force a 401 + refresh round too
    fake.add(make_raw("later"))
    run(s, 10, out=out, max_rounds=1)
    issued = [f"ya29.fake-access-token-{i}-abcdefghijkl" for i in range(1, fake.n_tok + 1)]
    secrets_ = [fake.refresh_token, "GOCSPX-client-secret-1", *issued]
    blob = out.getvalue() + caplog.text + state_path.read_bytes().decode("utf-8", "replace")
    assert out.getvalue().count("\n") == 3
    for sec in secrets_:
        assert sec not in blob


def test_secrets_never_reach_audit_or_executor_errors(tmp_path):
    from phishguard.connectors import gmail as gm
    from phishguard.connectors.oauth import GoogleRefreshToken
    from phishguard.mutating import AuditLog, Executor, MFAGateway
    from phishguard.mutating.mailbox import GmailRemediator, WriteHttpClient, remediation_handlers

    fake = FakeGmail(scope="https://www.googleapis.com/auth/gmail.readonly")  # write will fail with 403
    mid = fake.add(make_raw(**PHISH_RAW_KW))
    c = fake.client()
    auth = GoogleRefreshToken(HttpClient(c), "cid", Secret("GOCSPX-write-secret-9"), Secret(fake.refresh_token))
    rem = GmailRemediator(WriteHttpClient(c, auth=auth, auth_hosts=gm.AUTH_HOSTS))
    audit_path = tmp_path / "audit.jsonl"
    gw = MFAGateway(executor=Executor(remediation_handlers(rem)), audit=AuditLog(str(audit_path)))
    r = gw.submit("quarantine_email", {"provider": "gmail", "mailbox": rem.mailbox_key, "message_id": mid}, "worker")
    assert r.status == "executed" and r.result["ok"] is False
    blob = audit_path.read_text() + json.dumps(r.result) + json.dumps(gw.executor.ledger)
    for sec in (fake.refresh_token, "GOCSPX-write-secret-9", *fake.valid_tokens):
        assert sec not in blob


# ---------------------------------------------------------------------------------- webhooks
def _app(**kw):
    hits = []
    app = FastAPI()
    app.include_router(make_router(lambda p, h: hits.append((p, h)), **kw))
    return TestClient(app), hits


def test_graph_validation_handshake_and_client_state():
    cs = Secret("client-state-0123456789abcdef")
    c, hits = _app(graph_client_state=cs)
    r = c.post("/webhooks/graph?validationToken=Validation%3A+Testing+client+application")
    assert r.status_code == 200 and r.text == "Validation: Testing client application"
    assert r.headers["content-type"].startswith("text/plain") and r.headers["x-content-type-options"] == "nosniff"
    assert c.post("/webhooks/graph?validationToken=" + "<script>%0a").status_code == 400
    good = {"value": [{"clientState": "client-state-0123456789abcdef", "resource": "me/messages/1"}]}
    assert c.post("/webhooks/graph", json=good).status_code == 202 and hits == [("graph", "")]
    bad = {"value": [{"clientState": "guess", "resource": "me/messages/1"}]}
    assert c.post("/webhooks/graph", json=bad).status_code == 403 and len(hits) == 1
    assert c.post("/webhooks/graph", content=b"not json").status_code == 400
    c2, _ = _app()
    assert c2.post("/webhooks/graph", json=good).status_code == 404


@pytest.fixture(scope="module")
def rsa_key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks_for(key, kid="k1"):
    from jwt.algorithms import RSAAlgorithm

    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, alg="RS256", use="sig")
    handler = lambda req: httpx.Response(200, json={"keys": [jwk]})  # noqa: E731
    return JwksCache(HttpClient(httpx.Client(transport=httpx.MockTransport(handler))))


def _tok(key, **over):
    import jwt

    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": "https://hook.example/webhooks/gmail",
        "email": "push@proj.iam.gserviceaccount.com",
        "email_verified": True,
        "iat": now,
        "exp": now + 600,
    }
    claims.update(over)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})


def test_gmail_pubsub_jwt_validation(rsa_key):
    c, hits = _app(
        pubsub_audience="https://hook.example/webhooks/gmail",
        pubsub_service_account="push@proj.iam.gserviceaccount.com",
        jwks=_jwks_for(rsa_key),
    )
    data = base64.b64encode(json.dumps({"emailAddress": "me@example.com", "historyId": 99}).encode()).decode()
    body = {"message": {"data": data, "messageId": "1"}, "subscription": "projects/p/subscriptions/s"}

    def post(tok):
        return c.post("/webhooks/gmail", json=body, headers={"Authorization": f"Bearer {tok}"} if tok else {})

    assert post(_tok(rsa_key)).status_code == 204 and hits == [("gmail", "me@example.com")]
    from cryptography.hazmat.primitives.asymmetric import rsa

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    import jwt

    rejected = [
        None,
        _tok(rsa_key, aud="https://other.example/"),
        _tok(rsa_key, email="attacker@evil.iam.gserviceaccount.com"),
        _tok(rsa_key, email_verified=False),
        _tok(rsa_key, iss="https://evil.example"),
        _tok(rsa_key, exp=int(time.time()) - 3600),
        _tok(other),  # signed by someone else under our kid
        jwt.encode(
            {"aud": "https://hook.example/webhooks/gmail"},
            "attacker-chosen-hmac-secret-0123456789abcdef",
            algorithm="HS256",
            headers={"kid": "k1"},
        ),
        "eyJhbGciOiJub25lIn0.eyJhdWQiOiJ4In0.",  # alg=none
        "garbage",
    ]
    for t in rejected:
        assert post(t).status_code == 401, t
    assert len(hits) == 1


def test_self_improvement_cannot_patch_connectors_or_remediation_glue():
    from redteam.improve import ProtectedPathError, check_patch

    for path in (
        "phishguard/connectors/secrets.py",
        "phishguard/connectors/webhooks.py",
        "phishguard/mailbox_guard.py",
    ):
        diff = f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-x\n+y\n"
        with pytest.raises(ProtectedPathError):
            check_patch(diff)
