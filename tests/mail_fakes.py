"""Offline fakes of the Gmail API, Microsoft Graph and an IMAP server. No real network anywhere.

FakeGmail / FakeGraph are httpx.MockTransport handlers with just enough behaviour (paging, history,
delta, token endpoints, rate limits, write endpoints) to exercise the connectors and remediators.
FakeImapServer is a real socket server (optionally TLS with a throwaway self-signed certificate)
speaking the IMAP subset imaplib uses, so the stdlib client parses genuine protocol responses.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import re
import socket
import ssl
import threading
from email.message import EmailMessage
from urllib.parse import parse_qs, unquote, urlsplit

import httpx

GMAIL_READ = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_MODIFY = "https://www.googleapis.com/auth/gmail.modify"


def make_raw(subject="Hello", body="Plain note.", sender="anna@partner.example", n=0, **headers) -> bytes:
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "me@example.com"
    m["Subject"] = subject
    m["Message-ID"] = f"<msg-{n}-{abs(hash(subject)) % 10**8}@example>"
    m["Date"] = "Tue, 03 Mar 2026 10:00:00 +0000"
    for k, v in headers.items():
        m[k.replace("_", "-")] = v
    m.set_content(body)
    return bytes(m)


PHISH_RAW_KW = dict(
    subject="Urgent: verify your account now",
    body="Your mailbox will be suspended. Verify your password at http://192.168.10.5/login immediately. "
    "Wire transfer the invoice payment today.",
    sender="security@paypa1-support.example",
)


def _resp(status=200, data=None, headers=None, content=None):
    if content is not None:
        return httpx.Response(status, content=content, headers=headers or {})
    return httpx.Response(status, json=data if data is not None else {}, headers=headers or {})


class _TokenMixin:
    def _init_tokens(self, scope: str):
        self.scope = scope
        self.valid_tokens: set[str] = set()
        self.token_requests: list[dict] = []
        self.n_tok = 0
        self.expires_in = 3600

    def issue(self) -> str:
        self.n_tok += 1
        tok = f"ya29.fake-access-token-{self.n_tok}-abcdefghijkl"
        self.valid_tokens.add(tok)
        return tok

    def authed(self, request) -> bool:
        h = request.headers.get("authorization", "")
        return h.startswith("Bearer ") and h[7:] in self.valid_tokens


class FakeGmail(_TokenMixin):
    def __init__(self, scope: str = GMAIL_READ, refresh_token: str = "1//fake-refresh-token-0123456789"):
        self._init_tokens(scope)
        self.refresh_token = refresh_token
        self.messages: dict[str, dict] = {}  # id -> {"raw": bytes, "labels": set}
        self.order: list[str] = []  # oldest -> newest
        self.history: list[tuple[int, str, list[str]]] = []
        self.hid = 1000
        self.min_history = 0
        self.requests: list[httpx.Request] = []
        self.queue: list[httpx.Response] = []  # canned responses served before normal routing
        self.labels = {"INBOX": "INBOX", "SPAM": "SPAM", "TRASH": "TRASH", "UNREAD": "UNREAD"}
        self.modifications: list[tuple[str, dict]] = []
        self.n = 0
        self.raw_override: dict[str, str] = {}

    def add(self, raw: bytes, labels=("INBOX",)) -> str:
        self.n += 1
        mid = f"18c{self.n:05x}abc"
        self.messages[mid] = {"raw": raw, "labels": set(labels)}
        self.order.append(mid)
        self.hid += 7
        self.history.append((self.hid, mid, list(labels)))
        return mid

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.queue:
            return self.queue.pop(0)
        url = urlsplit(str(request.url))
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.hostname == "oauth2.googleapis.com":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            if form.get("grant_type") == "refresh_token" and form.get("refresh_token") != self.refresh_token:
                return _resp(400, {"error": "invalid_grant"})
            return _resp(200, {"access_token": self.issue(), "expires_in": self.expires_in, "scope": self.scope})
        if url.hostname != "gmail.googleapis.com":
            return _resp(404, {"error": "unknown host"})
        if not self.authed(request):
            return _resp(401, {"error": {"code": 401, "status": "UNAUTHENTICATED"}})
        path = url.path.removeprefix("/gmail/v1/users/me")
        if request.method == "GET" and path == "/profile":
            return _resp(200, {"emailAddress": "me@example.com", "historyId": str(self.hid)})
        if request.method == "GET" and path == "/messages":
            ids = [m for m in reversed(self.order) if q.get("labelIds", "INBOX") in self.messages[m]["labels"]]
            start = int(q.get("pageToken", "0"))
            size = int(q.get("maxResults", "100"))
            page = ids[start : start + size]
            data = {"messages": [{"id": i, "threadId": i} for i in page]}
            if start + size < len(ids):
                data["nextPageToken"] = str(start + size)
            return _resp(200, data)
        if request.method == "GET" and path == "/history":
            start_h = int(q["startHistoryId"])
            if start_h < self.min_history:
                return _resp(404, {"error": {"code": 404, "status": "NOT_FOUND"}})
            recs = [h for h in self.history if h[0] > start_h and q.get("labelId", "INBOX") in h[2]]
            off = int(q.get("pageToken", "0"))
            size = int(q.get("maxResults", "100"))
            page = recs[off : off + size]
            data = {
                "history": [
                    {"id": str(h), "messagesAdded": [{"message": {"id": mid, "labelIds": labels}}]}
                    for h, mid, labels in page
                ],
                "historyId": str(self.hid),
            }
            if off + size < len(recs):
                data["nextPageToken"] = str(off + size)
            return _resp(200, data)
        m = re.fullmatch(r"/messages/([\w-]+)", path)
        if request.method == "GET" and m and q.get("format") == "raw":
            mid = m.group(1)
            if mid not in self.messages:
                return _resp(404, {"error": {"code": 404}})
            raw = self.raw_override.get(mid) or base64.urlsafe_b64encode(self.messages[mid]["raw"]).decode().rstrip("=")
            return _resp(200, {"id": mid, "raw": raw})
        # --- write endpoints (remediation) ---
        if path == "/labels" and request.method == "GET":
            return _resp(200, {"labels": [{"id": v, "name": k} for k, v in self.labels.items()]})
        if path == "/labels" and request.method == "POST":
            body = json.loads(request.content)
            lid = f"Label_{len(self.labels)}"
            self.labels[body["name"]] = lid
            return _resp(200, {"id": lid, "name": body["name"]})
        m = re.fullmatch(r"/messages/([\w-]+)/(modify|trash)", path)
        if m and request.method == "POST":
            if self.scope == GMAIL_READ:
                return _resp(403, {"error": {"code": 403, "errors": [{"reason": "insufficientPermissions"}]}})
            mid, op = m.groups()
            body = json.loads(request.content or b"{}")
            self.modifications.append((mid, {"op": op, **body}))
            labs = self.messages[mid]["labels"]
            if op == "trash":
                labs.clear()
                labs.add("TRASH")
            else:
                labs.difference_update(body.get("removeLabelIds", []))
                labs.update(body.get("addLabelIds", []))
            return _resp(200, {"id": mid, "labelIds": sorted(labs)})
        if path == "/messages" and request.method == "POST":
            body = json.loads(request.content)
            raw = base64.urlsafe_b64decode(body["raw"] + "=" * (-len(body["raw"]) % 4))
            mid = self.add(raw, labels=tuple(body.get("labelIds", ["INBOX"])))
            self.modifications.append((mid, {"op": "insert"}))
            return _resp(200, {"id": mid})
        if path == "/watch" and request.method == "POST":
            return _resp(200, {"historyId": str(self.hid), "expiration": "1767225600000"})
        return _resp(404, {"error": {"code": 404, "status": "NOT_FOUND"}})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def fake_jwt(claims: dict) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(claims)}.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"


class FakeGraph(_TokenMixin):
    BASE = "/v1.0/me"

    def __init__(self, roles=("Mail.Read",), delegated_scope: str | None = "Mail.Read offline_access"):
        self._init_tokens(delegated_scope or "")
        self.roles = list(roles)
        self.delegated_scope = delegated_scope
        self.messages: dict[str, dict] = {}
        self.order: list[str] = []
        self.requests: list[httpx.Request] = []
        self.queue: list[httpx.Response] = []
        self.delta_tokens: dict[str, int] = {}  # token -> index into order already delivered
        self.page = 2
        self.n = 0
        self.refresh_tokens = {"M.R3_BAY.refresh-original-abcdef"}
        self.device_polls = ["authorization_pending", "slow_down", None]
        self.folders = {"inbox": "inbox", "junkemail": "junkemail", "deleteditems": "deleteditems"}
        self.moves: list[tuple[str, str]] = []
        self.patches: list[tuple[str, dict]] = []
        self.expired_tokens: set[str] = set()

    def add(self, raw: bytes) -> str:
        self.n += 1
        mid = f"AAMkAGI2TG93AAA{self.n:04d}="
        self.messages[mid] = {"raw": raw, "folder": "inbox", "categories": []}
        self.order.append(mid)
        return mid

    def _new_delta(self, upto: int) -> str:
        tok = f"dt{len(self.delta_tokens) + 1}"
        self.delta_tokens[tok] = upto
        return tok

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.queue:
            return self.queue.pop(0)
        url = urlsplit(str(request.url))
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.hostname == "login.microsoftonline.com":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            gt = form.get("grant_type")
            if url.path.endswith("/devicecode"):
                return _resp(
                    200,
                    {
                        "device_code": "DAQABAAEAAAD-device-code-secret",
                        "user_code": "ABCD-EFGH",
                        "verification_uri": "https://microsoft.com/devicelogin",
                        "interval": 5,
                        "expires_in": 900,
                    },
                )
            if gt == "urn:ietf:params:oauth:grant-type:device_code":
                state = self.device_polls.pop(0)
                if state:
                    return _resp(400, {"error": state})
                return _resp(
                    200,
                    {
                        "access_token": self.issue(),
                        "refresh_token": "M.R3_BAY.refresh-original-abcdef",
                        "expires_in": 3600,
                        "scope": self.delegated_scope,
                    },
                )
            if gt == "refresh_token":
                if form.get("refresh_token") not in self.refresh_tokens:
                    return _resp(400, {"error": "invalid_grant"})
                new_rt = f"M.R3_BAY.refresh-rotated-{len(self.token_requests)}-xyz"
                self.refresh_tokens = {new_rt}
                return _resp(
                    200,
                    {
                        "access_token": self.issue(),
                        "refresh_token": new_rt,
                        "expires_in": 3600,
                        "scope": self.delegated_scope,
                    },
                )
            if gt == "client_credentials":
                tok = fake_jwt({"roles": self.roles, "aud": "https://graph.microsoft.com"})
                self.valid_tokens.add(tok)
                return _resp(200, {"access_token": tok, "expires_in": 3599, "token_type": "Bearer"})
            return _resp(400, {"error": "unsupported_grant_type"})
        if url.hostname != "graph.microsoft.com":
            return _resp(404, {})
        if not self.authed(request):
            return _resp(401, {"error": {"code": "InvalidAuthenticationToken"}})
        path = unquote(url.path)
        base = self.BASE if path.startswith(self.BASE) else None
        if base is None:
            m = re.match(r"/v1\.0/users/([^/]+)", path)
            base = m.group(0) if m else ""
        rel = path[len(base) :]
        if request.method == "GET" and rel == "/mailFolders/inbox/messages/delta":
            if "$deltatoken" in q:
                tok = q["$deltatoken"]
                if tok not in self.delta_tokens:
                    return _resp(410, {"error": {"code": "syncStateNotFound"}})
                start = self.delta_tokens[tok]
            elif "$skiptoken" in q:
                start = int(q["$skiptoken"])
            else:
                start = len(self.order)  # $filter receivedDateTime ge now -> nothing yet
            ids = [i for i in self.order[start:] if self.messages[i]["folder"] == "inbox"]
            page, rest = ids[: self.page], ids[self.page :]
            data = {"value": [{"id": i, "receivedDateTime": "2026-03-03T10:00:00Z"} for i in page]}
            if rest:
                nxt = self.order.index(rest[0])
                data["@odata.nextLink"] = f"https://graph.microsoft.com{path}?$skiptoken={nxt}"
            else:
                data["@odata.deltaLink"] = (
                    f"https://graph.microsoft.com{path}?$deltatoken={self._new_delta(len(self.order))}"
                )
            return _resp(200, data)
        if request.method == "GET" and rel == "/mailFolders/inbox/messages":
            ids = [i for i in reversed(self.order) if self.messages[i]["folder"] == "inbox"]
            skip = int(q.get("$skip", "0"))
            top = int(q.get("$top", "10"))
            data = {"value": [{"id": i} for i in ids[skip : skip + top]]}
            if skip + top < len(ids):
                data["@odata.nextLink"] = f"https://graph.microsoft.com{path}?$skip={skip + top}&$top={top}"
            return _resp(200, data)
        m = re.fullmatch(r"/messages/([^/]+)/\$value", rel)
        if request.method == "GET" and m:
            mid = m.group(1)
            if mid not in self.messages:
                return _resp(404, {"error": {"code": "ErrorItemNotFound"}})
            return _resp(200, content=self.messages[mid]["raw"], headers={"content-type": "message/rfc822"})
        # --- write endpoints ---
        if rel == "/mailFolders" and request.method == "GET":
            name = re.search(r"displayName eq '([^']+)'", q.get("$filter", ""))
            vals = [{"id": v, "displayName": k} for k, v in self.folders.items() if name and k == name.group(1)]
            return _resp(200, {"value": vals})
        if rel == "/mailFolders" and request.method == "POST":
            body = json.loads(request.content)
            self.folders[body["displayName"]] = fid = f"folder-{len(self.folders)}"
            return _resp(201, {"id": fid, "displayName": body["displayName"]})
        m = re.fullmatch(r"/messages/([^/]+)/move", rel)
        if m and request.method == "POST":
            if "Mail.ReadWrite" not in self.roles and "Mail.ReadWrite" not in (self.delegated_scope or ""):
                return _resp(403, {"error": {"code": "ErrorAccessDenied"}})
            dest = json.loads(request.content)["destinationId"]
            self.messages[m.group(1)]["folder"] = dest
            self.moves.append((m.group(1), dest))
            return _resp(201, {"id": m.group(1)})
        m = re.fullmatch(r"/messages/([^/]+)", rel)
        if m and request.method == "GET":
            return _resp(200, {"id": m.group(1), "categories": self.messages[m.group(1)]["categories"]})
        if m and request.method == "PATCH":
            body = json.loads(request.content)
            self.messages[m.group(1)].update(body)
            self.patches.append((m.group(1), body))
            return _resp(200, {"id": m.group(1)})
        if path == "/v1.0/subscriptions" and request.method == "POST":
            body = json.loads(request.content)
            return _resp(201, {"id": "sub-1", "expirationDateTime": body["expirationDateTime"]})
        return _resp(404, {"error": {"code": "NotFound"}})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


# ------------------------------------------------------------------------------------- IMAP
def self_signed_cert(tmp_path):
    """A throwaway certificate for 127.0.0.1/localhost, so the TLS path is tested for real."""
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_p, key_p = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return str(cert_p), str(key_p)


class FakeImapServer:
    """IMAP4rev1 subset over a real socket. Records every command; tracks flags per message."""

    def __init__(
        self,
        user="me@example.com",
        password="app-password-abcd-efgh",
        token=None,
        tls_files=None,
        caps=("IMAP4rev1", "AUTH=PLAIN", "AUTH=XOAUTH2", "MOVE", "UIDPLUS", "ID"),
        require_id=False,
    ):
        self.user, self.password, self.token = user, password, token
        self.caps = list(caps)
        self.require_id = require_id
        self.folders: dict[str, dict] = {"INBOX": {"validity": 7, "next": 1, "msgs": {}}}
        self.commands: list[str] = []
        self.sessions = 0
        self._ctx = None
        if tls_files:
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ctx.load_cert_chain(*tls_files)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    # -- mailbox model --
    def add(self, raw: bytes, folder="INBOX", flags=()) -> int:
        f = self.folders.setdefault(folder, {"validity": 9, "next": 1, "msgs": {}})
        uid = f["next"]
        f["next"] += 1
        f["msgs"][uid] = {"raw": raw, "flags": set(flags)}
        return uid

    def renumber(self, folder="INBOX"):
        f = self.folders[folder]
        f["validity"] += 1
        msgs = list(f["msgs"].values())
        f["msgs"] = {}
        f["next"] = 1
        for m in msgs:
            f["msgs"][f["next"]] = m
            f["next"] += 1

    def close(self):
        self._stop = True
        self.sock.close()

    # -- protocol --
    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn):
        self.sessions += 1
        try:
            if self._ctx:
                conn = self._ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile("rb")
            w = conn.makefile("wb")
            state = {"auth": False, "folder": None, "readonly": True, "id_sent": False}

            def send(s):
                w.write(s if isinstance(s, bytes) else s.encode())
                w.flush()

            send("* OK FakeIMAP ready\r\n")
            while True:
                line = f.readline()
                if not line:
                    return
                text = line.decode("utf-8", "replace").rstrip("\r\n")
                lit = re.search(r"\{(\d+)\}$", text)
                literal = None
                if lit:
                    send("+ Ready\r\n")
                    literal = f.read(int(lit.group(1)))
                    f.readline()
                tag, _, rest = text.partition(" ")
                cmd, _, args = rest.partition(" ")
                cmd = cmd.upper()
                logged = text if cmd not in ("LOGIN",) else f"{tag} LOGIN {args.split(' ')[0]} ***"
                self.commands.append(logged)
                if cmd == "LOGOUT":
                    send("* BYE\r\n" + f"{tag} OK bye\r\n")
                    return
                self._dispatch(tag, cmd, args, literal, state, send, f)
        except (OSError, ssl.SSLError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self, tag, cmd, args, literal, st, send, f):
        if cmd == "CAPABILITY":
            send(f"* CAPABILITY {' '.join(self.caps)}\r\n{tag} OK done\r\n")
        elif cmd == "NOOP":
            send(f"{tag} OK done\r\n")
        elif cmd == "LOGIN":
            u, p = [x.strip('"') for x in args.split(" ", 1)]
            if u == self.user and p == self.password:
                st["auth"] = True
                send(f"{tag} OK logged in\r\n")
            else:
                send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
        elif cmd == "AUTHENTICATE":
            send("+ \r\n")
            resp = base64.b64decode(f.readline().strip()).decode()
            self.commands.append("<xoauth2 response>")
            if self.token and resp == f"user={self.user}\x01auth=Bearer {self.token}\x01\x01":
                st["auth"] = True
                send(f"{tag} OK authenticated\r\n")
            else:
                send("+ " + base64.b64encode(b'{"status":"401"}').decode() + "\r\n")
                f.readline()
                send(f"{tag} NO [AUTHENTICATIONFAILED] invalid token\r\n")
        elif cmd == "ID":
            st["id_sent"] = True
            send(f'* ID ("name" "FakeIMAP")\r\n{tag} OK done\r\n')
        elif cmd in ("SELECT", "EXAMINE"):
            if not st["auth"]:
                return send(f"{tag} BAD not authenticated\r\n")
            if self.require_id and not st["id_sent"]:
                return send(f"{tag} NO SELECT Unsafe Login. Please contact kefu@188.com for help\r\n")
            name = self._decode_name(args)
            if name not in self.folders:
                return send(f"{tag} NO no such folder\r\n")
            fo = self.folders[name]
            st["folder"], st["readonly"] = name, cmd == "EXAMINE"
            send(
                f"* {len(fo['msgs'])} EXISTS\r\n* OK [UIDVALIDITY {fo['validity']}] ok\r\n"
                f"* OK [UIDNEXT {fo['next']}] ok\r\n"
                f"{tag} OK [{'READ-ONLY' if st['readonly'] else 'READ-WRITE'}] {cmd} done\r\n"
            )
        elif cmd == "LIST":
            name = self._decode_name(args.split(" ", 1)[1])
            if name in self.folders:
                send(f'* LIST () "/" "{name}"\r\n')
            send(f"{tag} OK done\r\n")
        elif cmd == "CREATE":
            name = self._decode_name(args)
            self.folders.setdefault(name, {"validity": 11, "next": 1, "msgs": {}})
            send(f"{tag} OK created\r\n")
        elif cmd == "APPEND":
            name = self._decode_name(args.rsplit(" ", 1)[0])
            uid = self.add(literal, name)
            send(f"{tag} OK [APPENDUID {self.folders[name]['validity']} {uid}] appended\r\n")
        elif cmd == "UID":
            self._uid(tag, args, st, send)
        else:
            send(f"{tag} BAD unknown command\r\n")

    @staticmethod
    def _decode_name(s: str) -> str:
        s = s.strip()
        if s.startswith('"') and s.endswith('"'):
            s = s[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        if "&" in s:
            import base64 as b

            def dec(m):
                if m.group(1) == "":
                    return "&"
                data = m.group(1).replace(",", "/")
                return b.b64decode(data + "=" * (-len(data) % 4)).decode("utf-16-be")

            s = re.sub(r"&([A-Za-z0-9+,]*)-", dec, s)
        return s

    def _uid(self, tag, args, st, send):
        sub, _, rest = args.partition(" ")
        sub = sub.upper()
        fo = self.folders.get(st["folder"] or "")
        if fo is None:
            return send(f"{tag} BAD no folder selected\r\n")
        msgs = fo["msgs"]
        seqs = {u: i + 1 for i, u in enumerate(sorted(msgs))}
        if sub == "SEARCH":
            if rest.upper() == "ALL":
                hits = sorted(msgs)
            else:
                m = re.match(r"UID (\d+):\*", rest, re.I)
                lo = int(m.group(1))
                hits = [u for u in sorted(msgs) if u >= lo] or ([max(msgs)] if msgs else [])
            return send(f"* SEARCH {' '.join(map(str, hits))}\r\n{tag} OK done\r\n")
        uid_s, _, what = rest.partition(" ")
        uid = int(uid_s)
        if sub == "FETCH":
            if uid not in msgs:
                return send(f"{tag} OK done\r\n")
            m = msgs[uid]
            if "RFC822.SIZE" in what.upper():
                return send(f"* {seqs[uid]} FETCH (UID {uid} RFC822.SIZE {len(m['raw'])})\r\n{tag} OK done\r\n")
            if "BODY.PEEK[]" not in what.upper():
                m["flags"].add("\\Seen")  # a non-PEEK body fetch sets \Seen, like a real server
            send(f"* {seqs[uid]} FETCH (UID {uid} BODY[] {{{len(m['raw'])}}}\r\n".encode() + m["raw"] + b")\r\n")
            return send(f"{tag} OK done\r\n")
        if st["readonly"] and sub in ("STORE", "COPY", "MOVE", "EXPUNGE"):
            return send(f"{tag} NO mailbox is read-only\r\n")
        if sub == "STORE":
            flags = re.search(r"\((.*)\)", what).group(1).split()
            msgs[uid]["flags"].update(flags)
            return send(f"{tag} OK done\r\n")
        if sub in ("COPY", "MOVE"):
            dest = self._decode_name(what)
            if dest not in self.folders:
                return send(f"{tag} NO [TRYCREATE] no such folder\r\n")
            self.add(msgs[uid]["raw"], dest, msgs[uid]["flags"] - {"\\Deleted"})
            if sub == "MOVE":
                del msgs[uid]
            return send(f"{tag} OK done\r\n")
        if sub == "EXPUNGE":
            if uid in msgs and "\\Deleted" in msgs[uid]["flags"]:
                del msgs[uid]
            return send(f"{tag} OK done\r\n")
        send(f"{tag} BAD bad\r\n")
