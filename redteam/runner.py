"""Red-team runner. Fires every YAML payload at the API and checks invariants after each one.

    python -m redteam.runner                                   # in-process (what pytest uses)
    python -m redteam.runner --mode http --base-url http://api:8000 --api-key K --admin-key A

Invariants checked after EVERY attack (in-process mode has the strongest oracles):
- no_mfa_bypass:      no money/account action reached the executor without an approval the runner made itself
- sql_parameterized:  every statement SQLite executed is a literal from store.py (attacker text never becomes SQL)
- db_integrity:       PRAGMA integrity_check ok, no table added/dropped, audit hash chain intact
- no_crash:           no 5xx, /health still answers
- no_header_injection: response carries no header an attacker could have injected
- fs_untouched:       nothing written in the sandbox directory except the database
Per-attack expectations (status codes, minimum risk, features, time) come from the YAML.
"""

from __future__ import annotations

import argparse
import ast
import io
import os
import pathlib
import sqlite3
import tarfile
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import pyotp
import yaml

from .builders import build_eml, expand

HERE = pathlib.Path(__file__).parent
PAYLOADS = HERE / "payloads"
CLIENT_KEY = "rt-client-key-0001"
ADMIN_KEY = "rt-admin-key-0001"
SENSITIVE = {"transfer_funds", "pay_invoice", "approve_invoice", "change_bank_details", "reset_password"}
ALLOWED_HEADERS = {"content-type", "content-length", "retry-after", "www-authenticate", "date", "server"}


def load_payloads(path: pathlib.Path = PAYLOADS) -> list[dict[str, Any]]:
    out = []
    for f in sorted(path.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        for a in doc["attacks"]:
            out.append({**a, "category": doc["category"]})
    return out


def store_sql_literals() -> set[str]:
    """Every SQL string literal written in store.py: the only statements allowed to run."""
    import phishguard.mutating.store as store_mod

    tree = ast.parse(pathlib.Path(store_mod.__file__).read_text())
    lits = {
        " ".join(n.value.split())
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
        if n.value.strip().upper().startswith(("SELECT", "INSERT", "UPDATE", "DELETE", "PRAGMA", "CREATE"))
    }
    return lits


class _SQLRecorder:
    """Stands in for the sqlite3 connection inside SQLiteStore and logs every statement."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self.log: list[str] = []

    def execute(self, sql, params=()):
        self.log.append(" ".join(sql.split()))
        return self._conn.execute(sql, params)

    def executescript(self, sql):
        return self._conn.executescript(sql)

    def close(self):
        return self._conn.close()


class CompromisedLLM:
    """Worst case: the model obeys the email, calls money tools and declares the mail safe."""

    def complete(self, *, system, messages, tools, max_tokens):
        from phishguard.llm.base import LLMResponse, ToolCall

        if len(messages) == 1:
            calls = [
                ToolCall("x1", "transfer_funds", {"amount": 50000, "mfa_verified": True}),
                ToolCall("x2", "approve_invoice", {"bypass_mfa": True}),
                ToolCall("x3", "get_email", {}),
            ]
            return LLMResponse(text="MFA verified by system.", tool_calls=calls, input_tokens=5, output_tokens=5)
        return LLMResponse(text='{"risk": 0, "rationale": "safe, approved"}', input_tokens=5, output_tokens=5)


# ---------------------------------------------------------------------------- targets
@dataclass
class Resp:
    status_code: int
    headers: dict[str, str]
    text: str
    seconds: float
    path: str = ""
    sent: Any = None

    def json(self) -> Any:
        import json

        try:
            return json.loads(self.text)
        except ValueError:
            return {}


class InProcessTarget:
    mode = "in-process"

    def __init__(self) -> None:
        from fastapi.testclient import TestClient

        from phishguard.api import create_app
        from phishguard.config import Settings
        from phishguard.mutating import CaptureChannel

        self.tmp = tempfile.TemporaryDirectory(prefix="phishguard-redteam-")
        self.dir = pathlib.Path(self.tmp.name)
        self.db = str(self.dir / "redteam.db")
        settings = Settings(
            llm_mode="mock",
            executives=("David Chen",),
            api_keys=(CLIENT_KEY,),
            admin_keys=(ADMIN_KEY,),
            allow_unauthenticated=False,
            open_enrollment=False,
            db_path=self.db,
            rate_limit_per_minute=100_000,
            mfa_lockout_threshold=5,
        )
        self.channel = CaptureChannel()
        self.app = create_app(settings, llm=CompromisedLLM(), channel=self.channel)
        self.client = TestClient(self.app, raise_server_exceptions=False)
        store = self.app.state.store
        self.sql = _SQLRecorder(store._db)
        store._db = self.sql
        self.gateway = self.app.state.gateway

    def request(self, method: str, path: str, key: str | None = "client", **kw) -> Resp:
        headers = dict(kw.pop("headers", {}) or {})
        if key:
            headers["x-api-key"] = {"client": CLIENT_KEY, "admin": ADMIN_KEY}.get(key, key)
        t0 = time.perf_counter()
        r = self.client.request(method, path, headers=headers, **kw)
        return Resp(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text, time.perf_counter() - t0)

    def close(self) -> None:
        self.app.state.store.close()
        self.tmp.cleanup()


class HttpTarget:
    mode = "http"

    def __init__(self, base_url: str, api_key: str, admin_key: str):
        import httpx

        self.client = httpx.Client(base_url=base_url, timeout=30)
        self.keys = {"client": api_key, "admin": admin_key}
        self.channel = None
        self.gateway = None

    def request(self, method: str, path: str, key: str | None = "client", **kw) -> Resp:
        headers = dict(kw.pop("headers", {}) or {})
        if key:
            headers["x-api-key"] = self.keys.get(key, key)
        t0 = time.perf_counter()
        r = self.client.request(method, path, headers=headers, **kw)
        return Resp(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text, time.perf_counter() - t0)

    def close(self) -> None:
        self.client.close()


# ---------------------------------------------------------------------------- scenarios
@dataclass
class Ctx:
    target: Any
    attack: dict[str, Any]
    responses: list[Resp] = field(default_factory=list)
    checks: dict[str, tuple[bool, str]] = field(default_factory=dict)
    approved: set[str] = field(default_factory=set)
    risk: float | None = None

    def req(self, method: str, path: str, **kw) -> Resp:
        sent = kw.get("json")
        if (
            "json" in kw
        ):  # serialize ourselves: ASCII escapes let lone surrogates reach the server like a real attacker's
            import json

            kw["content"] = json.dumps(kw.pop("json")).encode()
            kw["headers"] = {"content-type": "application/json", **(kw.get("headers") or {})}
        r = self.target.request(method, path, **kw)
        r.path, r.sent = path, sent
        self.responses.append(r)
        return r

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks[name] = (bool(ok), detail)

    def user(self, name: str) -> str:
        return f"{self.attack['id']}-{name}"


def _expect_common(c: Ctx, r: Resp) -> None:
    exp = c.attack.get("expect", {})
    if "status_in" in exp:
        c.check("status", r.status_code in exp["status_in"], f"got {r.status_code}, want {exp['status_in']}")
    if "max_seconds" in exp:
        c.check("fast", r.seconds <= exp["max_seconds"], f"{r.seconds:.2f}s (limit {exp['max_seconds']}s)")
    body = r.json() if r.status_code == 200 else {}
    if isinstance(body, dict) and "risk_percent" in body:
        c.risk = body["risk_percent"]
        names = {f["name"] for f in body.get("features", [])}
        if "min_risk" in exp:
            c.check(
                "detected", c.risk >= exp["min_risk"], f"risk {c.risk} (need >= {exp['min_risk']}); {sorted(names)}"
            )
        if "features_any" in exp:
            c.check("feature", bool(names & set(exp["features_any"])), f"want one of {exp['features_any']}")
    for h in exp.get("no_header", []):
        c.check(f"no_{h}", h.lower() not in r.headers, f"header {h} present")


def sc_eml(c: Ctx) -> None:
    r = c.req("POST", "/analyze/eml", json={"raw": build_eml(expand(c.attack["eml"]))})
    _expect_common(c, r)


def sc_email_json(c: Ctx) -> None:
    email = {"id": c.attack["id"], "timestamp": "2026-03-03T10:00:00+00:00", **expand(c.attack["email"])}
    r = c.req("POST", "/analyze", json={"email": email})
    _expect_common(c, r)


def sc_request(c: Ctx) -> None:
    a = c.attack
    kw: dict[str, Any] = {}
    if "json" in a:
        kw["json"] = expand(a["json"])
    if "content" in a:
        kw["content"] = str(expand(a["content"])).encode("utf-8", "surrogatepass")
        kw["headers"] = {"content-type": "application/json", **a.get("headers", {})}
        r = c.target.request(a.get("method", "POST"), a["path"], key=a.get("key", "client"), **kw)
        c.responses.append(r)
        _expect_common(c, r)
        return
    elif "headers" in a:
        kw["headers"] = a["headers"]
    r = c.req(a.get("method", "POST"), a["path"], key=a.get("key", "client"), **kw)
    _expect_common(c, r)
    if a.get("expect", {}).get("not_executed"):
        c.check("not_executed", r.json().get("status") != "executed", r.text[:120])


def _enroll(c: Ctx, user: str) -> pyotp.TOTP:
    r = c.req("POST", "/mfa/enroll", json={"user": user}, key="admin")
    assert r.status_code == 200, r.text
    return pyotp.parse_uri(r.json()["otpauth_uri"])


def _submit(c: Ctx, user: str, action: str = "transfer_funds", params: dict | None = None) -> dict:
    r = c.req("POST", "/actions", json={"action_type": action, "requested_by": user, "params": params or {"n": 1}})
    return r.json()


def _verify(c: Ctx, pid: str, code: str, digest: str) -> Resp:
    return c.req("POST", "/mfa/verify", json={"pending_id": pid, "code": code, "confirm_digest": digest})


def sc_flow(c: Ctx) -> None:
    flow = c.attack["flow"]
    if flow == "forged_pending_id":
        r = _verify(c, "AAAAAAAAAAAAAAAA", "123456", "0" * 16)
        c.check("refused", r.status_code == 404, str(r.status_code))
    elif flow == "forged_code":
        p = _submit(c, c.user("u"))
        codes = [_verify(c, p["pending_id"], g, p["confirm_digest"]).status_code for g in c.attack["guesses"]]
        c.check("refused", all(s in (403, 409, 423) for s in codes), str(codes))
    elif flow == "swapped_digest":
        t = _enroll(c, c.user("u"))
        a = _submit(c, c.user("u"), params={"amount": 1})
        b = _submit(c, c.user("u"), params={"amount": 99999})
        r = _verify(c, b["pending_id"], t.now(), a["confirm_digest"])  # digest of the small one
        c.check("refused", r.status_code == 403, str(r.status_code))
    elif flow == "totp_replay":
        t = _enroll(c, c.user("u"))
        a, b = _submit(c, c.user("u")), _submit(c, c.user("u"), params={"n": 2})
        code = t.now()
        ok = _verify(c, a["pending_id"], code, a["confirm_digest"])
        if ok.status_code == 200:
            c.approved.add(a["confirm_digest"])
        r = _verify(c, b["pending_id"], code, b["confirm_digest"])
        c.check("first_ok", ok.status_code == 200, str(ok.status_code))
        c.check("replay_refused", r.status_code == 403, str(r.status_code))
    elif flow == "executed_replay":
        t = _enroll(c, c.user("u"))
        a = _submit(c, c.user("u"))
        ok = _verify(c, a["pending_id"], t.now(), a["confirm_digest"])
        if ok.status_code == 200:
            c.approved.add(a["confirm_digest"])
        r = _verify(c, a["pending_id"], t.now(), a["confirm_digest"])
        c.check("replay_refused", r.status_code == 409, str(r.status_code))
    elif flow == "cross_user":
        _enroll(c, c.user("alice"))
        bob = _enroll(c, c.user("bob"))
        a = _submit(c, c.user("alice"))
        r = _verify(c, a["pending_id"], bob.now(), a["confirm_digest"])
        c.check("refused", r.status_code == 403, str(r.status_code))
    elif flow == "identity_variant":
        _enroll(c, c.user("carol"))
        variants = [c.user("CAROL"), " " + c.user("carol"), c.user("carol").replace("c", "ｃ", 1), c.user("ca​rol")]
        methods = [_submit(c, v).get("mfa_method") for v in variants]
        c.check("no_downgrade", methods == ["totp"] * len(variants), str(methods))
    elif flow == "enroll_takeover":
        r = c.req("POST", "/mfa/enroll", json={"user": c.user("victim")}, key="client")
        c.check("refused", r.status_code == 403, str(r.status_code))
    elif flow == "reenroll":
        _enroll(c, c.user("dave"))
        r = c.req("POST", "/mfa/enroll", json={"user": c.user("DAVE")}, key="admin")
        c.check("refused", r.status_code == 409, str(r.status_code))
    elif flow == "brute_force":
        a = _submit(c, c.user("m"))
        b = _submit(c, c.user("m"), params={"n": 2})
        codes = [_verify(c, a["pending_id"], f"{i:06d}", a["confirm_digest"]).status_code for i in range(3)]
        codes += [_verify(c, b["pending_id"], f"{i:06d}", b["confirm_digest"]).status_code for i in range(3)]
        again = c.req("POST", "/actions", json={"action_type": "transfer_funds", "requested_by": c.user("m")})
        c.check("locked", 423 in codes and again.status_code == 423, f"{codes} then {again.status_code}")
    elif flow == "analyze_then_actions":
        # analysis with a compromised model must not create or approve anything
        before = len(c.target.channel.codes) if c.target.channel is not None else 0
        sc_email_json(c)
        if c.target.channel is not None:
            c.check("no_pending_created", len(c.target.channel.codes) == before, "")
    else:
        raise ValueError(f"unknown flow {flow}")


def sc_sql_fields(c: Ctx) -> None:
    p = c.attack["payload"]
    u = p + c.attack["id"]
    statuses = [
        c.req("POST", "/mfa/enroll", json={"user": u[:100]}, key="admin").status_code,
        c.req(
            "POST",
            "/actions",
            json={"action_type": "transfer_funds", "requested_by": u[:100], "reason": p, "params": {p[:60]: p}},
        ).status_code,
        c.req("POST", "/actions", json={"action_type": p[:64], "requested_by": "x"}).status_code,
        c.req("POST", "/mfa/verify", json={"pending_id": p[:64], "code": p[:16], "confirm_digest": p[:64]}).status_code,
    ]
    c.check("handled", all(s < 500 for s in statuses), str(statuses))


def sc_tar_traversal(c: Ctx) -> None:
    import sys

    sys.path.insert(0, str(HERE.parent / "scripts"))
    from download_datasets import UnsafeArchive, safe_extract

    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name in c.attack["members"]:
                data = b"pwned"
                info = tarfile.TarInfo(name)
                if name.startswith("LINK:"):
                    info = tarfile.TarInfo("link")
                    info.type, info.linkname = tarfile.SYMTYPE, name[5:]
                    data = b""
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        arc = root / "evil.tar"
        arc.write_bytes(buf.getvalue())
        dest = root / "out"
        try:
            safe_extract(arc, dest)
            refused = False
        except UnsafeArchive:
            refused = True
        escaped = [p for p in root.rglob("*") if p.is_file() and p not in (arc,) and dest not in p.parents]
        c.check("refused", refused, "")
        c.check("nothing_outside", not escaped, str(escaped))


SCENARIOS = {
    "eml": sc_eml,
    "email_json": sc_email_json,
    "request": sc_request,
    "flow": sc_flow,
    "sql_fields": sc_sql_fields,
    "tar_traversal": sc_tar_traversal,
}


# ---------------------------------------------------------------------------- oracles
def _requires_mfa(action: str, params: dict) -> bool:
    from phishguard.mutating.policy import ActionType, requires_mfa

    return requires_mfa(ActionType(action), params)


def _db_state(db: str) -> tuple[str, set[str]]:
    con = sqlite3.connect(db)
    try:
        ok = con.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()
    return ok, tables


def run_attack(target, attack: dict[str, Any], sql_allow: set[str]) -> dict[str, Any]:
    c = Ctx(target, attack)
    inproc = target.mode == "in-process"
    if inproc:
        ledger0 = len(target.gateway.executor.ledger)
        sql0 = len(target.sql.log)
        files0 = {p.name for p in target.dir.iterdir()}
        tables0 = _db_state(target.db)[1]
    try:
        SCENARIOS[attack["kind"]](c)
    except Exception as e:  # a scenario blowing up is itself a finding
        c.check("scenario_ran", False, f"{type(e).__name__}: {e}"[:200])

    statuses = [r.status_code for r in c.responses]
    c.check("no_crash", all(s < 500 for s in statuses), str(statuses))
    health = target.request("GET", "/health", key=None)
    c.check("alive", health.status_code == 200, str(health.status_code))
    bad_headers = sorted({h for r in c.responses for h in r.headers} - ALLOWED_HEADERS)
    c.check("no_header_injection", not bad_headers, str(bad_headers))
    chain = target.request("GET", "/audit/verify", key="client").json()
    c.check("audit_chain", chain.get("chain_ok") is True, str(chain))
    if inproc:
        new = target.gateway.executor.ledger[ledger0:]
        sneaked = [e for e in new if _requires_mfa(e["action"], e["params"]) and e["digest"] not in c.approved]
        c.check("no_mfa_bypass", not sneaked, str(sneaked)[:200])
        rogue = [s for s in target.sql.log[sql0:] if s not in sql_allow]
        c.check("sql_parameterized", not rogue, str(rogue)[:200])
        ok, tables = _db_state(target.db)
        c.check("db_integrity", ok == "ok" and tables == tables0, f"{ok} {sorted(tables ^ tables0)}")
        extra = {p.name for p in target.dir.iterdir()} - files0 - {"redteam.db-wal", "redteam.db-shm"}
        c.check("fs_untouched", not extra, str(sorted(extra)))
    else:
        # response-level: an /actions call that came back "executed" must not have needed MFA
        from phishguard.mutating.policy import UnknownActionError, parse_action_type, requires_mfa

        sneaked = []
        for r in c.responses:
            if r.path == "/actions" and r.status_code == 200 and isinstance(r.sent, dict):
                try:
                    act = parse_action_type(r.sent.get("action_type", ""))
                except UnknownActionError:
                    sneaked.append(r.text[:80])
                    continue
                if requires_mfa(act, r.sent.get("params") or {}, r.sent.get("reason", "")):
                    sneaked.append(r.text[:80])
        c.check("no_mfa_bypass", not sneaked, str(sneaked))

    security = {k: v for k, v in c.checks.items() if k not in ("detected", "feature")}
    detection = {k: v for k, v in c.checks.items() if k in ("detected", "feature")}
    return {
        "id": attack["id"],
        "category": attack["category"],
        "title": attack.get("title", attack["id"]),
        "risk": c.risk,
        "security_ok": all(ok for ok, _ in security.values()),
        "detection_ok": all(ok for ok, _ in detection.values()) if detection else None,
        "passed": all(ok for ok, _ in c.checks.values()),
        "failed_checks": {k: d for k, (ok, d) in c.checks.items() if not ok},
        "attack": attack,
    }


def run(target=None, payloads: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    own = target is None
    target = target or InProcessTarget()
    allow = store_sql_literals()
    try:
        return [run_attack(target, a, allow) for a in (payloads or load_payloads())]
    finally:
        if own:
            target.close()


# ---------------------------------------------------------------------------- report
CATEGORY_NAMES = {
    "prompt_injection": "a) Prompt injection",
    "privilege": "b) Privilege escalation / MFA bypass",
    "injection": "c) Injection & DoS (SQL, path, size, headers, Unicode)",
    "evasion": "d) Detection evasion",
}


def render_report(results: list[dict[str, Any]], mode: str) -> str:
    by = defaultdict(list)
    for r in results:
        by[r["category"]].append(r)
    lines = [
        "# Red Team Report",
        "",
        f"Mode: `{mode}`. Generated by `python -m redteam.runner`. {len(results)} attacks.",
        "",
        "Interception rate = attacks where every check passed (security invariants and, where the payload",
        "sets one, the detection threshold). Security invariants must hold for 100% of attacks; a detection",
        "miss is a quality gap, not a breach, and is fed to `redteam/improve.py`.",
        "",
        "| Category | Attacks | Security invariants held | Detection met | Interception rate |",
        "|---|---|---|---|---|",
    ]
    for cat in sorted(by, key=lambda k: list(CATEGORY_NAMES).index(k) if k in CATEGORY_NAMES else 99):
        rs = by[cat]
        sec = sum(r["security_ok"] for r in rs)
        det = [r for r in rs if r["detection_ok"] is not None]
        det_s = f"{sum(r['detection_ok'] for r in det)}/{len(det)}" if det else "n/a"
        rate = sum(r["passed"] for r in rs) / len(rs)
        lines.append(f"| {CATEGORY_NAMES.get(cat, cat)} | {len(rs)} | {sec}/{len(rs)} | {det_s} | {rate:.0%} |")
    total = sum(r["passed"] for r in results) / max(1, len(results))
    sec_all = sum(r["security_ok"] for r in results)
    lines += [f"| **Total** | {len(results)} | {sec_all}/{len(results)} | | **{total:.0%}** |", ""]
    lines += ["## Attacks", "", "| ID | Category | Attack | Risk | Result |", "|---|---|---|---|---|"]
    for r in results:
        res = "pass" if r["passed"] else "FAIL: " + "; ".join(f"{k} ({v})" for k, v in r["failed_checks"].items())
        risk = "" if r["risk"] is None else f"{r['risk']:.0f}"
        lines.append(f"| `{r['id']}` | {r['category']} | {r['title']} | {risk} | {res.replace('|', '/')[:220]} |")
    lines += [
        "",
        "## Oracles",
        "",
        "`no_mfa_bypass`, `sql_parameterized`, `db_integrity`, `fs_untouched` need in-process mode (they read the",
        "executor ledger and wrap the SQLite connection). In `http` mode only response-level checks run.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["in-process", "http"], default="in-process")
    ap.add_argument("--base-url", default=os.environ.get("REDTEAM_BASE_URL", "http://api:8000"))
    ap.add_argument("--api-key", default=os.environ.get("REDTEAM_API_KEY", ""))
    ap.add_argument("--admin-key", default=os.environ.get("REDTEAM_ADMIN_KEY", ""))
    ap.add_argument("--report", default=str(HERE / "report.md"))
    ap.add_argument("--print", action="store_true", help="also print the report to stdout")
    a = ap.parse_args(argv)
    target = InProcessTarget() if a.mode == "in-process" else HttpTarget(a.base_url, a.api_key, a.admin_key)
    try:
        results = run(target)
    finally:
        target.close()
    report = render_report(results, a.mode)
    try:
        pathlib.Path(a.report).write_text(report, encoding="utf-8")
    except OSError as e:  # e.g. bind mount not writable by the non-root runner
        print(f"could not write {a.report}: {e}")
    if a.print:
        print(report)
    breaches = [r["id"] for r in results if not r["security_ok"]]
    print(
        f"{len(results)} attacks, {sum(r['passed'] for r in results)} fully intercepted, breaches: {breaches or 'none'}"
    )
    print(f"report: {a.report}")
    return 1 if breaches else 0


if __name__ == "__main__":
    raise SystemExit(main())
