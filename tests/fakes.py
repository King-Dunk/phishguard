"""In-process fakes of the Gmail API, Microsoft Graph and an IMAP server. No real network.

The HTTP fakes plug into httpx.MockTransport; the IMAP fake is a real TCP (optionally TLS) server
speaking enough IMAP4rev1 for imaplib, so the connector's actual protocol parsing is exercised.
"""

from __future__ import annotations

import base64
import json
import re
import socketserver
import ssl
import threading
from urllib.parse import parse_qs, unquote, urlparse

import httpx

TOKEN = "ya29.fake-access-token-0001"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class _Base:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.forced: list[httpx.Response] = []  # responses returned before normal handling (429, 503...)
        self.valid_tokens = {TOKEN}
        self.reject_next_token = False

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=self.transport())

    def handle(self, r: httpx.Request) -> httpx.Response:
        self.calls.append((r.method, r.url.path))
        if self.forced:
            return self.forced.pop(0)
        tok = r.headers.get("Authorization", "").removeprefix("Bearer ")
        if self.reject_next_token:
            self.reject_next_token = False
            return httpx.Response(401, json={"error": {"code": 401, "status": "UNAUTHENTICATED"}})
        if tok not in self.valid_tokens:
            return httpx.Response(401, json={"error": {"code": 401, "status": "UNAUTHENTICATED"}})
        return self.route(r)

    def route(self, r: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise NotImplementedError

    def methods(self) -> set[str]:
        return {m for m, _ in self.calls}


class FakeGmail(_Base):
    """messages: ordered oldest -> newest. Each add() bumps historyId like Gmail does."""

    def __init__(self):
        super().__init__()
        self.msgs: dict[str, dict] = {}
        self.order: list[str] = []
        self.history: list[tuple[int, str]] = []  # (historyId, message id)
        self.hid = 1000
        self.min_history = 0
        self.labels = {"INBOX": "INBOX", "SPAM": "SPAM", "TRASH": "TRASH"}
        self.inserted: list[bytes] = []

    def add(self, mid: str, raw: bytes, labels=("INBOX",), size: int | None = None) -> None:
        self.hid += 1
        self.msgs[mid] = {"raw": raw, "labels": set(labels), "size": size if size is not None else len(raw)}
        self.order.append(mid)
        self.history.append((self.hid, mid))

    def inbox(self) -> list[str]:
        return [m for m in self.order if "INBOX" in self.msgs[m]["labels"]]

    def route(self, r: httpx.Request) -> httpx.Response:
        path = r.url.path.removeprefix("/gmail/v1/users/me")
        q = {k: v[0] for k, v in parse_qs(r.url.query.decode()).items()}
        if path == "/profile":
            return httpx.Response(200, json={"emailAddress": "user@example.com", "historyId": str(self.hid)})
        if path == "/messages" and r.method == "GET":
            ids = list(reversed(self.inbox()))  # newest first, like Gmail
            start = int(q.get("pageToken", 0))
            n = int(q.get("maxResults", 100))
            page = ids[start : start + n]
            body = {"messages": [{"id": i, "threadId": i} for i in page], "resultSizeEstimate": len(ids)}
            if start + n < len(ids):
                body["nextPageToken"] = str(start + n)
            return httpx.Response(200, json=body)
        if path == "/history":
            start = int(q["startHistoryId"])
            if start < self.min_history:
                return httpx.Response(404, json={"error": {"code": 404, "status": "NOT_FOUND"}})
            items = [(h, m) for h, m in self.history if h > start and "INBOX" in self.msgs[m]["labels"]]
            off = int(q.get("pageToken", 0))
            per = 2  # tiny pages to exercise pagination
            page = items[off : off + per]
            body = {
                "historyId": str(self.hid),
                "history": [{"id": str(h), "messagesAdded": [{"message": {"id": m}}]} for h, m in page],
            }
            if off + per < len(items):
                body["nextPageToken"] = str(off + per)
            return httpx.Response(200, json=body)
        m = re.fullmatch(r"/messages/([^/]+)", path)
        if m and r.method == "GET":
            mid = unquote(m.group(1))
            if mid not in self.msgs:
                return httpx.Response(404, json={"error": {"code": 404}})
            msg = self.msgs[mid]
            if q.get("format") == "minimal":
                return httpx.Response(
                    200, json={"id": mid, "sizeEstimate": msg["size"], "labelIds": sorted(msg["labels"])}
                )
            return httpx.Response(200, json={"id": mid, "raw": _b64url(msg["raw"])})
        if path == "/watch" and r.method == "POST":
            return httpx.Response(200, json={"historyId": str(self.hid), "expiration": "1893456000000"})
        # ---- write endpoints (used by the remediation writer, never by the read connector)
        if path == "/labels" and r.method == "GET":
            return httpx.Response(200, json={"labels": [{"id": v, "name": k} for k, v in self.labels.items()]})
        if path == "/labels" and r.method == "POST":
            name = json.loads(r.content)["name"]
            self.labels[name] = f"Label_{len(self.labels)}"
            return httpx.Response(200, json={"id": self.labels[name], "name": name})
        if path == "/messages/batchModify" and r.method == "POST":
            b = json.loads(r.content)
            for mid in b["ids"]:
                self.msgs[mid]["labels"] |= set(b.get("addLabelIds", []))
                self.msgs[mid]["labels"] -= set(b.get("removeLabelIds", []))
            return httpx.Response(204)
        m = re.fullmatch(r"/messages/([^/]+)/trash", path)
        if m and r.method == "POST":
            self.msgs[m.group(1)]["labels"] = {"TRASH"}
            return httpx.Response(200, json={"id": m.group(1)})
        if path == "/messages/import" or path == "/messages":
            b = json.loads(r.content)
            raw = base64.urlsafe_b64decode(b["raw"] + "=" * (-len(b["raw"]) % 4))
            self.inserted.append(raw)
            nid = f"ins{len(self.inserted)}"
            self.add(nid, raw, labels=tuple(b.get("labelIds", ["INBOX"])))
            return httpx.Response(200, json={"id": nid})
        return httpx.Response(404, json={"error": {"code": 404, "status": "NOT_FOUND", "path": path}})


class FakeGraph(_Base):
    def __init__(self):
        super().__init__()
        self.msgs: dict[str, dict] = {}
        self.order: list[str] = []
        self.expired_tokens: set[str] = set()
        self.max_delta_page = 2
        self.subscriptions: list[dict] = []

    def add(self, mid: str, raw: bytes, folder: str = "inbox") -> None:
        self.msgs[mid] = {"raw": raw, "folder": folder, "categories": []}
        self.order.append(mid)

    def inbox(self) -> list[str]:
        return [m for m in self.order if self.msgs[m]["folder"] == "inbox"]

    def route(self, r: httpx.Request) -> httpx.Response:
        u = urlparse(str(r.url))
        path = u.path.removeprefix("/v1.0").removeprefix("/me")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        base = "https://graph.microsoft.com/v1.0/me"
        if path == "/mailFolders/inbox/messages" and r.method == "GET":
            ids = list(reversed(self.inbox()))
            skip, top = int(q.get("$skip", 0)), int(q.get("$top", 10))
            body = {"value": [{"id": i} for i in ids[skip : skip + top]]}
            if skip + top < len(ids):
                body["@odata.nextLink"] = f"{base}/mailFolders/inbox/messages?$top={top}&$skip={skip + top}"
            return httpx.Response(200, json=body)
        if path == "/mailFolders/inbox/messages/delta":
            # initial round: enumerate current inbox; follow-ups: state = number of messages already seen
            if "$deltatoken" in q:
                tok = q["$deltatoken"]
                if tok in self.expired_tokens:
                    return httpx.Response(410, json={"error": {"code": "SyncStateNotFound"}})
                state = int(tok.split("-")[1])
                changes = self.order[state:]
                pos = 0
            else:
                state, pos = int(q.get("from", 0)), int(q.get("$skiptoken", 0))
                changes = self.order[state:]
            page = changes[pos : pos + self.max_delta_page]
            items = [
                {"id": i} if self.msgs[i]["folder"] == "inbox" else {"id": i, "@removed": {"reason": "changed"}}
                for i in page
            ]
            body = {"value": items}
            if pos + self.max_delta_page < len(changes):
                body["@odata.nextLink"] = (
                    f"{base}/mailFolders/inbox/messages/delta?$skiptoken={pos + self.max_delta_page}&from={state}"
                )
            else:
                body["@odata.deltaLink"] = f"{base}/mailFolders/inbox/messages/delta?$deltatoken=d-{len(self.order)}"
            return httpx.Response(200, json=body)
        m = re.fullmatch(r"/messages/([^/]+)/\$value", path)
        if m:
            mid = unquote(m.group(1))
            return httpx.Response(200, content=self.msgs[mid]["raw"], headers={"Content-Type": "text/plain"})
        if u.path == "/v1.0/subscriptions" and r.method == "POST":
            self.subscriptions.append(json.loads(r.content))
            return httpx.Response(201, json={"id": "sub-1", **self.subscriptions[-1]})
        # ---- write endpoints (remediation only)
        m = re.fullmatch(r"/messages/([^/]+)/move", path)
        if m and r.method == "POST":
            mid = unquote(m.group(1))
            self.msgs[mid]["folder"] = json.loads(r.content)["destinationId"].lower()
            return httpx.Response(201, json={"id": mid})
        m = re.fullmatch(r"/messages/([^/]+)", path)
        if m and r.method == "GET":
            return httpx.Response(
                200, json={"id": m.group(1), "categories": self.msgs[unquote(m.group(1))]["categories"]}
            )
        if m and r.method == "PATCH":
            self.msgs[unquote(m.group(1))]["categories"] = json.loads(r.content)["categories"]
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"error": {"code": "ResourceNotFound", "path": path}})


# ------------------------------------------------------------------------------------------ IMAP
class ImapState:
    def __init__(self, user="user@example.com", password="app-pass-123456", token=TOKEN):
        self.user, self.password, self.token = user, password, token
        self.uidvalidity = 42
        self.folders: dict[str, list[tuple[int, bytes, set]]] = {"INBOX": [], "Junk": [], "Trash": []}
        self.next_uid = 1
        self.commands: list[str] = []
        self.sent_id = False
        self.caps = "IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2 MOVE UIDPLUS ID"

    def add(self, raw: bytes, folder="INBOX") -> int:
        uid = self.next_uid
        self.next_uid += 1
        self.folders[folder].append((uid, raw, set()))
        return uid

    def renumber(self) -> None:
        self.uidvalidity += 1
        self.folders = {f: [(i + 1, raw, fl) for i, (_, raw, fl) in enumerate(ms)] for f, ms in self.folders.items()}
        self.next_uid = max((len(m) for m in self.folders.values()), default=0) + 1


_TOK = re.compile(r'"((?:[^"\\]|\\.)*)"|(\S+)')


def _args(s: str) -> list[str]:
    return [a if a else b for a, b in _TOK.findall(s)]


def _uidset(spec: str, uids: list[int]) -> list[int]:
    out = []
    top = max(uids, default=0)
    for part in spec.split(","):
        if ":" in part:
            a, b = part.split(":")
            lo = int(a)
            hi = top if b == "*" else int(b)
            if b == "*" and lo > top:
                lo = hi = top  # RFC 3501: "*" is the largest UID, so N:* always matches it
            out += [u for u in uids if min(lo, hi) <= u <= max(lo, hi)]
        else:
            out += [u for u in uids if u == int(part)]
    return sorted(set(out))


class _Handler(socketserver.StreamRequestHandler):
    def send(self, line: str | bytes) -> None:
        self.wfile.write(line if isinstance(line, bytes) else line.encode())

    def handle(self) -> None:  # noqa: C901 - a protocol state machine
        st: ImapState = self.server.state
        selected, readonly, authed = None, True, False
        self.send(f"* OK [CAPABILITY {st.caps}] fake IMAP ready\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            tag, _, rest = text.partition(" ")
            cmd, _, arg = rest.partition(" ")
            cmd = cmd.upper()
            uid_cmd = None
            if cmd == "UID":
                uid_cmd, _, arg = arg.partition(" ")
                uid_cmd = uid_cmd.upper()
            st.commands.append(f"{cmd} {uid_cmd or ''}".strip())
            if cmd == "CAPABILITY":
                self.send(f"* CAPABILITY {st.caps}\r\n{tag} OK done\r\n")
            elif cmd == "LOGIN":
                u, p = _args(arg)[:2]
                authed = u == st.user and p == st.password
                self.send(
                    f"{tag} OK logged in\r\n" if authed else f"{tag} NO [AUTHENTICATIONFAILED] bad credentials\r\n"
                )
            elif cmd == "AUTHENTICATE":
                self.send("+ \r\n")
                resp = base64.b64decode(self.rfile.readline().strip()).decode()
                authed = resp == f"user={st.user}\x01auth=Bearer {st.token}\x01\x01"
                self.send(
                    f"{tag} OK authenticated\r\n" if authed else f"{tag} NO [AUTHENTICATIONFAILED] invalid token\r\n"
                )
            elif cmd == "ID":
                st.sent_id = True
                self.send(f'* ID ("name" "fake")\r\n{tag} OK ID done\r\n')
            elif not authed:
                self.send(f"{tag} BAD authenticate first\r\n")
            elif cmd in ("EXAMINE", "SELECT"):
                name = _args(arg)[0]
                if name not in st.folders:
                    self.send(f"{tag} NO no such folder\r\n")
                    continue
                selected, readonly = name, cmd == "EXAMINE"
                n = len(st.folders[name])
                self.send(
                    f"* {n} EXISTS\r\n* OK [UIDVALIDITY {st.uidvalidity}] ok\r\n* OK [UIDNEXT {st.next_uid}] ok\r\n"
                )
                self.send(f"{tag} OK [{'READ-ONLY' if readonly else 'READ-WRITE'}] {cmd} done\r\n")
            elif cmd == "UID" and uid_cmd == "SEARCH":
                uids = [u for u, _, fl in st.folders[selected] if "\\Deleted" not in fl]
                a = _args(arg)
                hit = uids if a[0].upper() == "ALL" else _uidset(a[1], uids)
                self.send(f"* SEARCH {' '.join(map(str, hit))}\r\n{tag} OK search done\r\n")
            elif cmd == "UID" and uid_cmd == "FETCH":
                spec, _, what = arg.partition(" ")
                msgs = st.folders[selected]
                for seq, (u, raw, fl) in enumerate(msgs, 1):
                    if u not in _uidset(spec, [m[0] for m in msgs]):
                        continue
                    if "RFC822.SIZE" in what:
                        self.send(f"* {seq} FETCH (UID {u} RFC822.SIZE {len(raw)})\r\n")
                    else:
                        if "PEEK" not in what:
                            fl.add("\\Seen")
                        self.send(f"* {seq} FETCH (UID {u} BODY[] {{{len(raw)}}}\r\n".encode() + raw + b")\r\n")
                self.send(f"{tag} OK fetch done\r\n")
            elif readonly and selected and cmd in ("UID", "EXPUNGE", "STORE", "COPY", "MOVE"):
                self.send(f"{tag} NO [READ-ONLY] mailbox opened with EXAMINE\r\n")
            elif cmd == "UID" and uid_cmd in ("MOVE", "COPY"):
                spec, _, dest = arg.partition(" ")
                dest = _args(dest)[0]
                msgs = st.folders[selected]
                hit = set(_uidset(spec, [m[0] for m in msgs]))
                for u, raw, fl in list(msgs):
                    if u in hit:
                        st.add(raw, dest)
                        if uid_cmd == "MOVE":
                            msgs.remove((u, raw, fl))
                self.send(f"{tag} OK {uid_cmd} done\r\n")
            elif cmd == "UID" and uid_cmd == "STORE":
                spec, _, rest2 = arg.partition(" ")
                op, _, flags = rest2.partition(" ")
                for u, _raw, fl in st.folders[selected]:
                    if u in _uidset(spec, [m[0] for m in st.folders[selected]]):
                        names = set(flags.strip("()").split())
                        fl |= names if op.startswith("+") else set()
                        fl -= names if op.startswith("-") else set()
                self.send(f"{tag} OK store done\r\n")
            elif cmd == "UID" and uid_cmd == "EXPUNGE":
                st.folders[selected] = [m for m in st.folders[selected] if "\\Deleted" not in m[2]]
                self.send(f"{tag} OK expunge done\r\n")
            elif cmd == "APPEND":
                self._append(tag, arg, st)
            elif cmd == "CREATE":
                st.folders.setdefault(_args(arg)[0], [])
                self.send(f"{tag} OK created\r\n")
            elif cmd == "LOGOUT":
                self.send(f"* BYE bye\r\n{tag} OK logout\r\n")
                return
            elif cmd == "NOOP":
                self.send(f"{tag} OK noop\r\n")
            else:
                self.send(f"{tag} BAD unknown command {cmd}\r\n")

    def _append(self, tag: str, arg: str, st: ImapState) -> None:
        m = re.search(r"\{(\d+)\}$", arg)
        folder = _args(arg)[0]
        n = int(m.group(1))
        self.send("+ ready\r\n")
        data = self.rfile.read(n)
        self.rfile.readline()
        st.folders.setdefault(folder, [])
        st.add(data, folder)
        self.send(f"{tag} OK [APPENDUID {st.uidvalidity} {st.next_uid - 1}] append done\r\n")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, state: ImapState, tls_ctx: ssl.SSLContext | None):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.state, self.tls_ctx = state, tls_ctx

    def get_request(self):
        sock, addr = super().get_request()
        if self.tls_ctx:
            sock = self.tls_ctx.wrap_socket(sock, server_side=True)
        return sock, addr


class FakeImapServer:
    def __init__(self, state: ImapState | None = None, tls_ctx: ssl.SSLContext | None = None):
        self.state = state or ImapState()
        self.srv = _Server(self.state, tls_ctx)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


def self_signed_tls(tmp_path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """(server context, client context that trusts only this cert) for 127.0.0.1 / localhost."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = tmp_path / "cert.pem"
    key_pem = tmp_path / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_pem, key_pem)
    client = ssl.create_default_context(cafile=str(cert_pem))
    return server, client
