"""Scanner and worker: incremental cursor, idempotency, dedupe, malformed/large mail, retries."""

import io
import json
import threading

import pytest

from phishguard.agent import PhishingAgent
from phishguard.config import Settings
from phishguard.connectors import CheckpointStore, MailboxScanner
from phishguard.connectors.base import ConnectorError, MailboxConnector, MessageRef, OverPrivilegedCredential
from phishguard.connectors.worker import main as worker_main
from phishguard.connectors.worker import run
from phishguard.llm import MockLLM
from phishguard.readonly import EmlTooLarge
from tests.mail_fakes import PHISH_RAW_KW, FakeGmail, make_raw
from tests.test_connectors_providers import gmail_conn


class ListConnector(MailboxConnector):
    """In-memory connector: cursor = number of messages already listed."""

    provider = "fake"

    def __init__(self):
        self.msgs: list[tuple[str, bytes | Exception]] = []
        self.fetches: list[str] = []
        self.fail_list = False

    @property
    def mailbox_key(self):
        return "fake:box"

    def add(self, mid, raw):
        self.msgs.append((mid, raw))

    def initial_cursor(self):
        return str(len(self.msgs))

    def list_new(self, cursor):
        if self.fail_list:
            raise ConnectorError("provider down")
        if cursor is None:
            return [], self.initial_cursor()
        return [MessageRef(m) for m, _ in self.msgs[int(cursor) :]], str(len(self.msgs))

    def list_recent(self, n):
        return [MessageRef(m) for m, _ in reversed(self.msgs)][:n]

    def fetch_raw(self, ref):
        self.fetches.append(ref.provider_id)
        val = dict(self.msgs)[ref.provider_id]
        if isinstance(val, Exception):
            raise val
        return val


@pytest.fixture
def agent():
    return PhishingAgent(MockLLM(), Settings(llm_mode="mock"))


def scanner(conn, agent, sink=None, **kw):
    return MailboxScanner(conn, agent, CheckpointStore(":memory:"), sink=sink, **kw)


def test_first_poll_starts_from_now_then_scans_new_mail(agent):
    c = ListConnector()
    c.add("old", make_raw("old"))
    s = scanner(c, agent)
    assert s.poll_once() == [] and c.fetches == []
    c.add("p1", make_raw(**PHISH_RAW_KW))
    c.add("b1", make_raw("Lunch on Friday?", body="See you at noon."))
    v = {x.provider_id: x for x in s.poll_once()}
    assert set(v) == {"p1", "b1"}
    assert v["p1"].is_phishing and v["p1"].risk_percent >= 35 and v["p1"].top_features
    assert not v["b1"].is_phishing and v["b1"].status == "scanned"
    assert s.poll_once() == []


def test_backfill_on_first_run(agent):
    c = ListConnector()
    for i in range(5):
        c.add(f"m{i}", make_raw(f"s{i}", n=i))
    s = scanner(c, agent, backfill=3)
    assert [v.provider_id for v in s.poll_once()] == ["m2", "m3", "m4"]


def test_same_message_never_scanned_twice_even_after_crash_before_cursor_saved(agent):
    c = ListConnector()
    s = scanner(c, agent)
    s.poll_once()
    c.add("a", make_raw("a"))
    c.add("b", make_raw("b"))
    seen = []
    s.sink = lambda v: seen.append(v.provider_id)
    orig = s.state.set_cursor
    s.state.set_cursor = lambda *a: (_ for _ in ()).throw(RuntimeError("crash"))
    with pytest.raises(RuntimeError):
        s.poll_once()
    s.state.set_cursor = orig
    c.fetches.clear()
    assert s.poll_once() == []  # re-listed, but both already seen: no download, no rescan, no second action
    assert c.fetches == [] and seen == ["a", "b"]


def test_content_hash_dedupes_renumbered_copies(agent):
    c = ListConnector()
    s = scanner(c, agent)
    s.poll_once()
    raw = make_raw("same")
    c.add("uidv7:1", raw)
    assert len(s.poll_once()) == 1
    c.add("uidv8:1", raw)  # same bytes, new id (IMAP UIDVALIDITY change, copy in another folder)
    assert s.poll_once() == [] and s.last_stats.skipped_duplicate == 1


def test_malformed_and_large_messages_are_reported_not_fatal(agent):
    c = ListConnector()
    s = scanner(c, agent)
    s.poll_once()
    c.add("garbage", b"\x00\xff\xfe not a mail at all \r\n\r\n\x00")
    c.add("bomb", b"Content-Type: multipart/mixed; boundary=a\r\n\r\n" + b"boundary=x " * 300)
    c.add("big", EmlTooLarge("too big"))
    c.add("ok", make_raw("fine"))
    v = {x.provider_id: x for x in s.poll_once()}
    assert v["bomb"].status == "rejected" and "too many" in v["bomb"].detail.lower()
    assert v["big"].status == "rejected" and v["big"].detail.startswith("too_large")
    assert v["garbage"].status in ("scanned", "rejected")
    assert v["ok"].status == "scanned"
    assert s.poll_once() == []  # rejected ones are not retried forever


def test_transient_download_errors_are_retried_then_reported(agent):
    c = ListConnector()
    s = scanner(c, agent)
    s.poll_once()
    c.add("flaky", ConnectorError("503 after retries"))
    assert s.poll_once() == [] and s.state.retries("fake:box") == ["flaky"]
    c.msgs[0] = ("flaky", make_raw("recovered"))
    assert [v.provider_id for v in s.poll_once()] == ["flaky"]
    c.add("dead", ConnectorError("always failing"))
    s.poll_once()
    s.poll_once()
    out = s.poll_once()
    assert [v.status for v in out] == ["error"] and s.state.retries("fake:box") == []


def test_sink_failure_does_not_stop_the_scan(agent):
    c = ListConnector()
    s = scanner(c, agent, sink=lambda v: 1 / 0)
    s.poll_once()
    c.add("a", make_raw("a"))
    c.add("b", make_raw("b"))
    out = s.poll_once()
    assert len(out) == 2 and all("sink_failed" in v.detail for v in out)


def test_scan_recent_shows_cached_verdicts_instead_of_rescanning(agent):
    c = ListConnector()
    for i in range(3):
        c.add(f"m{i}", make_raw(f"s{i}", n=i))
    s = scanner(c, agent)
    first = s.scan_recent(3)
    assert [v.cached for v in first] == [False] * 3
    c.fetches.clear()
    again = s.scan_recent(3)
    assert [v.cached for v in again] == [True] * 3 and c.fetches == []
    assert [v.risk_percent for v in again] == [v.risk_percent for v in first]


def test_end_to_end_gmail_incremental_and_idempotent(agent, tmp_path):
    fake = FakeGmail()
    fake.add(make_raw("before start"))
    st = CheckpointStore(str(tmp_path / "state.db"))
    s = MailboxScanner(gmail_conn(fake), agent, st)
    assert s.poll_once() == []
    p = fake.add(make_raw(**PHISH_RAW_KW))
    out = s.poll_once()
    assert [v.provider_id for v in out] == [p] and out[0].is_phishing
    # restart with a fresh process/connector: the state DB carries cursor + seen-set
    s2 = MailboxScanner(gmail_conn(fake), agent, CheckpointStore(str(tmp_path / "state.db")))
    assert s2.poll_once() == []
    raws = [r for r in fake.requests if "format=raw" in str(r.url)]
    assert len(raws) == 1
    assert oct((tmp_path / "state.db").stat().st_mode & 0o777) == "0o600"


def test_worker_run_backs_off_on_provider_errors_and_stops_on_config_errors(agent):
    c = ListConnector()
    s = scanner(c, agent)
    c.fail_list = True
    waits = []

    class Ev(threading.Event):
        def wait(self, timeout=None):
            waits.append(timeout)
            return False

    run(s, 10, out=io.StringIO(), trigger=Ev(), max_rounds=3)
    assert waits == [20, 40]  # 10 * 2**n
    c.fail_list = False

    def over(_):
        raise OverPrivilegedCredential("write scope")

    c.list_new = over
    with pytest.raises(OverPrivilegedCredential):
        run(s, 10, out=io.StringIO(), max_rounds=1)


def test_worker_emits_json_lines_and_runs_maintenance(agent):
    c = ListConnector()
    s = scanner(c, agent)
    s.poll_once()
    c.add("p", make_raw(**PHISH_RAW_KW))
    out = io.StringIO()
    calls = []
    t = [0.0]

    def clock():
        t[0] += 100
        return t[0]

    run(s, 10, out=out, max_rounds=1, maintenance=[(50.0, lambda: calls.append(1))], clock=clock)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["provider_id"] == "p" and lines[0]["is_phishing"] is True
    assert calls == [1]


def test_worker_main_reports_config_errors_cleanly(capsys):
    assert worker_main(["--provider", "imap", "--once"], env={}) == 2
    with pytest.raises(SystemExit):
        worker_main(["--provider", "gmail", "--interval", "1"], env={})
