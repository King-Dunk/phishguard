# Connecting a real mailbox

This guide connects PhishGuard to Gmail / Google Workspace, Microsoft 365 / Outlook.com, or any IMAP mailbox (iCloud, Yahoo, Fastmail, QQ, 163, Zoho, ...). It is written for someone who has never registered an OAuth app. Allow 15-30 minutes for Google or Microsoft, 5 minutes for IMAP.

> **Status.** The connectors were tested only against offline fakes of each API (see [Testing](#what-was-and-wasnt-tested)). They have not yet been run against a real Google, Microsoft or IMAP account. Expect to be the first, and please report what breaks.

**Two rules before you start**

1. **Keep every credential outside the repository folder.** PhishGuard refuses secret files inside it. Use `~/.config/phishguard/`, and make each file readable only by you: `chmod 600 <file>`. PhishGuard refuses files other users can read.
2. **Start read-only.** Scanning needs only read access (`gmail.readonly`, `Mail.Read`). Write access (quarantine, labels, banners) is a separate, optional credential you add later, in [step 5](#5-optional-let-phishguard-act-on-phishing).

```bash
mkdir -p ~/.config/phishguard && chmod 700 ~/.config/phishguard
pip install -r requirements.txt
```

Contents: [1. Gmail](#1-gmail--google-workspace) · [2. Microsoft 365 / Outlook.com](#2-microsoft-365--outlookcom) · [3. IMAP](#3-imap-icloud-yahoo-fastmail-qq-163-zoho-) · [4. Run the scanner](#4-run-the-scanner) · [5. Remediation](#5-optional-let-phishguard-act-on-phishing) · [6. Push notifications](#6-optional-push-notifications-instead-of-polling) · [Reference](#environment-variable-reference)

Console menu names below are as of late 2026. Google and Microsoft rename things often; if a name doesn't match, search the console for the quoted term.

---

## 1. Gmail / Google Workspace

Choose **A** for your own mailbox (personal Gmail or one Workspace user), or **B** for a Workspace admin scanning users' mailboxes without each user signing in.

### A. Your own mailbox (OAuth "Desktop app")

1. Open <https://console.cloud.google.com/>, sign in, and create a project (top bar, project picker, "New project"), e.g. `phishguard`.
2. **Enable the Gmail API**: "APIs & Services" > "Library" > search "Gmail API" > "Enable".
3. **Consent screen**: "Google Auth Platform" (older consoles: "OAuth consent screen") > "Get started".
   - App name: `PhishGuard`; support email: yours.
   - Audience: **Internal** if you're on Google Workspace and only your organization will use it; otherwise **External**.
   - Under "Data Access" > "Add or remove scopes", add exactly `https://www.googleapis.com/auth/gmail.readonly`. Don't add anything else.
   - External apps start in **Testing**: under "Audience" > "Test users", add your own Gmail address.
4. **Create the client**: "Clients" (or "Credentials" > "Create credentials" > "OAuth client ID") > Application type **Desktop app** > Create > **Download JSON**.
5. Move the file and lock it down:
   ```bash
   mv ~/Downloads/client_secret_*.json ~/.config/phishguard/gmail-client.json
   chmod 600 ~/.config/phishguard/gmail-client.json
   export PHISHGUARD_GMAIL_CLIENT_FILE=~/.config/phishguard/gmail-client.json
   ```
6. **Sign in once**:
   ```bash
   python scripts/scan_mailbox.py --provider gmail --authorize
   ```
   A browser opens. Pick your account, accept "View your email messages and settings". You may see "Google hasn't verified this app": it's your own app, so click "Continue". The terminal prints `Stored refresh token 'gmail:read'`. The token lives in `~/.config/phishguard/tokens.json` (mode 0600).

**Known catch:** while an External app is in *Testing*, Google expires its refresh tokens after 7 days, so you'll need to re-run `--authorize` weekly. `gmail.readonly` is a *restricted* scope, and publishing an External app to Production requires Google's verification. For a personal tool, re-authorizing weekly is the practical option. Internal (Workspace) apps don't have this limit.

### B. Google Workspace with a service account (domain-wide delegation)

Needs a Workspace super admin.

1. In the Cloud project from A (steps 1-2), go to "IAM & Admin" > "Service accounts" > "Create service account" (e.g. `phishguard-reader`). No project roles are needed.
2. Open the account > "Keys" > "Add key" > "Create new key" > JSON. Save it as `~/.config/phishguard/gmail-sa.json` and run `chmod 600` on it. If key creation is blocked, your organization enforces `iam.disableServiceAccountKeyCreation`; ask your admin.
3. Copy the account's **Unique ID** (numeric client ID) from its details page.
4. In <https://admin.google.com/>: "Security" > "Access and data control" > "API controls" > "Manage Domain Wide Delegation" > "Add new". Client ID: the Unique ID. Scope: `https://www.googleapis.com/auth/gmail.readonly`. Authorize.
5. Configure:
   ```bash
   export PHISHGUARD_GMAIL_AUTH=service_account
   export PHISHGUARD_GMAIL_SA_KEY_FILE=~/.config/phishguard/gmail-sa.json
   export PHISHGUARD_GMAIL_USER=alice@yourcompany.com   # the mailbox to scan
   ```
   No `--authorize` step is needed.

**Know what you granted:** domain-wide delegation lets this key read *every* mailbox in the domain. Treat the key file like a domain admin password, rotate it, and don't reuse the service account for anything else.

---

## 2. Microsoft 365 / Outlook.com

Choose **A** (delegated, device code) for your own work or personal mailbox, or **B** (application, client credentials) for an admin scanning mailboxes unattended.

### A. Your own mailbox (device code sign-in)

1. Open <https://entra.microsoft.com/> (or the Azure portal, "Microsoft Entra ID") > "App registrations" > "New registration".
   - Name: `PhishGuard`.
   - Supported account types: for **Outlook.com / Hotmail**, choose one that includes *personal Microsoft accounts*. For a work mailbox, choose "this organizational directory only".
   - Redirect URI: leave empty.
2. In the new app: "Authentication" > "Advanced settings" > **Allow public client flows: Yes** > Save. Device code sign-in needs this.
3. "API permissions" > "Add a permission" > "Microsoft Graph" > **Delegated permissions** > tick **Mail.Read** > Add. Remove `User.Read` if you like; nothing else is needed. Some organizations require an admin to click "Grant admin consent".
4. From "Overview", copy the **Application (client) ID**, and for work accounts the **Directory (tenant) ID**.
5. Configure and sign in:
   ```bash
   export PHISHGUARD_GRAPH_CLIENT_ID=<application-client-id>
   export PHISHGUARD_GRAPH_TENANT=consumers        # Outlook.com/Hotmail; use your tenant ID for work accounts
   python scripts/scan_mailbox.py --provider graph --authorize
   ```
   The terminal says "open https://microsoft.com/devicelogin and enter the code ABCD-EFGH". Do that in any browser, sign in, and accept "Read your mail". The refresh token is stored in `~/.config/phishguard/tokens.json`; Microsoft rotates it on every use and PhishGuard writes the new one back.

### B. Unattended scanning in a Microsoft 365 tenant (app-only)

Needs a Global Administrator or Privileged Role Administrator for consent.

1. Register an app as in A step 1 (single tenant).
2. "API permissions" > "Add a permission" > "Microsoft Graph" > **Application permissions** > **Mail.Read** > Add > **Grant admin consent for <tenant>**.
3. "Certificates & secrets" > "New client secret". Copy the **Value** right away (it's shown once) into `~/.config/phishguard/graph-secret`, then `chmod 600` it.
4. **Restrict which mailboxes the app can read.** Application `Mail.Read` covers *every* mailbox in the tenant until you scope it. In Exchange Online PowerShell, use RBAC for Applications (recommended), or the older Application Access Policy, e.g.:
   ```powershell
   New-ApplicationAccessPolicy -AppId <application-client-id> -PolicyScopeGroupId phishguard-scanned@contoso.com `
       -AccessRight RestrictAccess -Description "PhishGuard may read only these mailboxes"
   ```
   Check Microsoft's current documentation for the exact commands; the point is not to leave tenant-wide read access in place.
5. Configure:
   ```bash
   export PHISHGUARD_GRAPH_AUTH=app
   export PHISHGUARD_GRAPH_TENANT=<directory-tenant-id>
   export PHISHGUARD_GRAPH_CLIENT_ID=<application-client-id>
   export PHISHGUARD_GRAPH_CLIENT_SECRET_FILE=~/.config/phishguard/graph-secret
   export PHISHGUARD_GRAPH_MAILBOX=alice@contoso.com
   ```

PhishGuard checks the token it receives. If the read app also holds `Mail.ReadWrite` or `Mail.Send`, it refuses to scan (override: `PHISHGUARD_ALLOW_OVERPRIVILEGED_READ=1`).

---

## 3. IMAP (iCloud, Yahoo, Fastmail, QQ, 163, Zoho, ...)

IMAP has no read-only credential: an app password can do anything a mail client can. PhishGuard still only reads. It opens the folder with `EXAMINE` and downloads with `BODY.PEEK[]`, so even the "read" status doesn't change, and tests check this. Use an **app password**, never your real account password: it can be revoked on its own and doesn't bypass 2-step verification for anything else.

1. Create an app password (or authorization code) with your provider:

   | Preset | Server | How to get the password |
   |---|---|---|
   | `icloud` | imap.mail.me.com:993 | account.apple.com > Sign-In and Security > App-Specific Passwords. Username: your full iCloud address |
   | `yahoo` | imap.mail.yahoo.com:993 | Yahoo Account security > Generate app password |
   | `aol` | imap.aol.com:993 | AOL Account security > Generate app password |
   | `fastmail` | imap.fastmail.com:993 | Settings > Privacy & Security > Integrations > App passwords (access: IMAP) |
   | `qq` | imap.qq.com:993 | QQ Mail Settings > Account > enable IMAP/SMTP; use the authorization code (授权码) it shows |
   | `163` / `126` / `yeah` | imap.163.com / imap.126.com / imap.yeah.net :993 | Settings > POP3/SMTP/IMAP > enable IMAP; use the authorization code (授权码). PhishGuard sends the IMAP `ID` command NetEase requires |
   | `zoho` | imap.zoho.com:993 (EU `.eu`, India `.in`) | Enable IMAP in Zoho Mail settings; with 2FA, create an application-specific password |
   | `gmx` | imap.gmx.com:993 (Germany: imap.gmx.net) | Enable IMAP in GMX settings |
   | `yandex` | imap.yandex.com:993 | Yandex ID > Security > App passwords |
   | `gmail` | imap.gmail.com:993 | App password (needs 2-Step Verification). Prefer section 1: the Gmail API supports a read-only scope; IMAP doesn't |
   | `outlook` | outlook.office365.com:993 | Basic auth is off; XOAUTH2 only. Prefer section 2 (Graph) |

2. Save the password to a file and configure:
   ```bash
   printf '%s' 'abcd-efgh-ijkl-mnop' > ~/.config/phishguard/imap-password && chmod 600 ~/.config/phishguard/imap-password
   export PHISHGUARD_IMAP_PRESET=icloud
   export PHISHGUARD_IMAP_USER=you@icloud.com
   export PHISHGUARD_IMAP_PASSWORD_FILE=~/.config/phishguard/imap-password
   ```
   For a server not in the table: `PHISHGUARD_IMAP_HOST=mail.example.com` (port 993 by default).

**TLS only.** Port 993 with certificate verification. Plaintext IMAP (port 143 without TLS) is refused. For a local test server only, set both `PHISHGUARD_IMAP_TLS=0` and `PHISHGUARD_IMAP_ALLOW_PLAINTEXT=1`.

**XOAUTH2 (Gmail or Outlook over IMAP).** Set `PHISHGUARD_IMAP_AUTH=xoauth2` and `PHISHGUARD_IMAP_OAUTH_PROVIDER=google|microsoft`, configure the Google client file or Microsoft client ID as in sections 1/2, but add the IMAP scope to the app instead: `https://mail.google.com/` (Google; full access, the only scope Gmail IMAP accepts) or `IMAP.AccessAsUser.All` (Microsoft, delegated). Then run `python scripts/scan_mailbox.py --provider imap --authorize`.

---

## 4. Run the scanner

**One-off: scan the last N messages** (read-only, prints a table):

```bash
python scripts/scan_mailbox.py --provider gmail --last 20
python scripts/scan_mailbox.py --provider graph --last 50 --json     # one JSON verdict per line
```

```
  risk  verdict  from                             subject                                            top features
  73.3  PHISH    security@paypa1-support.example  Urgent: verify your account now                    link_ip_host+28.4, urgency_language+16.0, credential_request+16.0
   1.0  ok       anna@partner.example             Team lunch                                         no_authentication+1.0

2 message(s), 1 flagged at threshold 35.
```

(Example output from the offline fake IMAP server.) Messages already scanned are shown from the checkpoint store with `(cached)` and aren't downloaded or analyzed again.

**Continuous: the polling worker** (read-only; one JSON line per new message on stdout):

```bash
python -m phishguard.connectors.worker --provider gmail --interval 60
python -m phishguard.connectors.worker --provider graph --backfill 20 --output ~/phishguard-verdicts.jsonl
```

- The first run starts from *now* (no backlog), plus `--backfill N` recent messages if you ask.
- Progress (cursor and seen messages) is in `~/.phishguard/connector_state.db` (mode 0600; override with `--state` or `PHISHGUARD_CONNECTOR_STATE`). Restarting never rescans a message.
- Rate limits (HTTP 429/503, Gmail `rateLimitExceeded`) are retried with `Retry-After`; provider outages back off up to 15 minutes. Credential problems stop the worker with a clear message.
- Scoring settings are the same as for the API: `PHISHGUARD_THRESHOLD`, `PHISHGUARD_TRUSTED_DOMAINS`, `PHISHGUARD_LLM_MODE`, and so on.

---

## 5. Optional: let PhishGuard act on phishing

Remediation runs through the MFA gateway like every other state change, with a **separate write credential** that the read-only scanner never loads.

| Action (`--action`) | Gmail | Microsoft 365 | IMAP | MFA? |
|---|---|---|---|---|
| `quarantine` | label `PhishGuard/Quarantine`, out of Inbox | folder `PhishGuard Quarantine` | folder `PhishGuard-Quarantine` | no |
| `junk` | Spam | Junk Email | provider's Junk folder | no |
| `label` | label `PhishGuard/Suspicious` | category | IMAP keyword | no |
| `banner` | warning copy in Inbox, original quarantined | not supported (use an Exchange transport rule) | warning copy in Inbox, original quarantined | no |
| delete / release from quarantine | Trash / back to Inbox | Deleted Items / Inbox | Trash / n.a. | **always** (two factors) |
| any action on more than 10 messages at once | | | | **always** (two factors) |

1. Mint the write credential:
   - **Gmail OAuth:** add the scope `https://www.googleapis.com/auth/gmail.modify` to the consent screen, then run `python scripts/scan_mailbox.py --provider gmail --authorize --write`. It is stored separately in `~/.config/phishguard/tokens-write.json`.
   - **Gmail service account:** create a *second* service account with delegation for `gmail.modify` only, and set `PHISHGUARD_GMAIL_WRITE_SA_KEY_FILE`.
   - **Microsoft delegated:** add the delegated permission `Mail.ReadWrite` (to the same app, or a second one: `PHISHGUARD_GRAPH_WRITE_CLIENT_ID`), then run `python scripts/scan_mailbox.py --provider graph --authorize --write`.
   - **Microsoft app-only:** register a *second* app with application `Mail.ReadWrite`, scoped to the same mailboxes, and set `PHISHGUARD_GRAPH_WRITE_CLIENT_ID` and `PHISHGUARD_GRAPH_WRITE_CLIENT_SECRET_FILE`.
   - **IMAP:** set `PHISHGUARD_IMAP_WRITE_PASSWORD_FILE` (it can be the same app password; setting it is the explicit opt-in).
   - **Banners:** also set `PHISHGUARD_BANNER_KEY_FILE` to a file holding a long random string (`openssl rand -hex 32`).
2. Run:
   ```bash
   python -m phishguard.mailbox_guard --provider gmail --action label --action quarantine
   ```
   Actions are written to the hash-chained audit log (`PHISHGUARD_DB_PATH` / `PHISHGUARD_AUDIT_LOG`). The worker never approves MFA itself: anything that needs MFA stays pending and is logged. "MFA" here is the same two-factor policy as for payments (two different methods, at least one TOTP or passkey; see the README's MFA section). Approval happens in the process that holds the pending action; the worker has no approval interface yet, so held mailbox actions currently expire unless approved programmatically through `gateway.verify_factor`.

Keep the write credential out of a scan-only deployment entirely. Then a bug or compromise in the scanner can't change mail.

---

## 6. Optional: push notifications instead of polling

Polling every 60 s is fine for a few mailboxes. To react within seconds, run the worker with its own small webhook server behind HTTPS (a reverse proxy such as Caddy or nginx with a real certificate). A notification only means "poll now"; what to fetch is always decided from PhishGuard's own cursor.

**Microsoft Graph**

```bash
python -m phishguard.connectors.worker --provider graph --webhooks --host 127.0.0.1 --port 8081 \
    --graph-notification-url https://phishguard.example.com/webhooks/graph
```

The worker creates the subscription, answers Graph's `validationToken` handshake, rejects notifications whose `clientState` doesn't match (a random secret per run, or `PHISHGUARD_GRAPH_CLIENT_STATE`), and renews every 48 h.

**Gmail (Cloud Pub/Sub push)**

1. Cloud console > "Pub/Sub" > create a topic, e.g. `phishguard`. On the topic's permissions, give `gmail-api-push@system.gserviceaccount.com` the **Pub/Sub Publisher** role.
2. Create a **push** subscription to `https://phishguard.example.com/webhooks/gmail` with **authentication enabled**: choose a service account (e.g. `phishguard-push@<project>.iam.gserviceaccount.com`) and set the audience to the same URL.
3. Run:
   ```bash
   export PHISHGUARD_PUBSUB_AUDIENCE=https://phishguard.example.com/webhooks/gmail
   export PHISHGUARD_PUBSUB_SERVICE_ACCOUNT=phishguard-push@<project>.iam.gserviceaccount.com
   python -m phishguard.connectors.worker --provider gmail --webhooks --gmail-topic projects/<project>/topics/phishguard
   ```
   Each push carries a Google-signed token. PhishGuard verifies the signature against Google's published keys, plus the audience, issuer, expiry and service-account email. The Gmail watch is renewed daily.

---

## Environment variable reference

| Variable | Used for |
|---|---|
| `PHISHGUARD_TOKEN_FILE` / `PHISHGUARD_WRITE_TOKEN_FILE` | refresh token stores (default `~/.config/phishguard/tokens.json` / `tokens-write.json`, mode 0600) |
| `PHISHGUARD_CONNECTOR_STATE` | checkpoint DB (default `~/.phishguard/connector_state.db`) |
| `PHISHGUARD_POLL_INTERVAL` | worker interval in seconds (default 60, minimum 5) |
| `PHISHGUARD_ALLOW_OVERPRIVILEGED_READ=1` | accept a read credential that also has write scopes (not recommended) |
| `PHISHGUARD_ALLOW_INSECURE_SECRET_PERMS=1` | accept group/world-readable secret files (not recommended) |
| `PHISHGUARD_GMAIL_AUTH` | `oauth` (default) or `service_account` |
| `PHISHGUARD_GMAIL_CLIENT_FILE` | Desktop OAuth client JSON |
| `PHISHGUARD_GMAIL_SA_KEY_FILE` / `PHISHGUARD_GMAIL_WRITE_SA_KEY_FILE` | service account keys (read / write) |
| `PHISHGUARD_GMAIL_USER` | `me` (default) or the mailbox address (required with a service account) |
| `PHISHGUARD_GRAPH_AUTH` | `device` (default) or `app` |
| `PHISHGUARD_GRAPH_TENANT` | tenant ID, or `common` / `consumers` / `organizations` (device only) |
| `PHISHGUARD_GRAPH_CLIENT_ID`, `PHISHGUARD_GRAPH_CLIENT_SECRET[_FILE]` | app registration (secret: app-only) |
| `PHISHGUARD_GRAPH_WRITE_CLIENT_ID`, `PHISHGUARD_GRAPH_WRITE_CLIENT_SECRET[_FILE]` | separate write app |
| `PHISHGUARD_GRAPH_MAILBOX`, `PHISHGUARD_GRAPH_FOLDER` | mailbox UPN (required for app-only), folder (default `inbox`) |
| `PHISHGUARD_IMAP_PRESET`, `PHISHGUARD_IMAP_HOST`, `PHISHGUARD_IMAP_PORT`, `PHISHGUARD_IMAP_FOLDER` | server and folder |
| `PHISHGUARD_IMAP_USER`, `PHISHGUARD_IMAP_PASSWORD[_FILE]`, `PHISHGUARD_IMAP_WRITE_PASSWORD[_FILE]` | login (read / write) |
| `PHISHGUARD_IMAP_AUTH=xoauth2`, `PHISHGUARD_IMAP_OAUTH_PROVIDER` | XOAUTH2 via Google or Microsoft |
| `PHISHGUARD_IMAP_TLS=0` + `PHISHGUARD_IMAP_ALLOW_PLAINTEXT=1` | plaintext, local test servers only |
| `PHISHGUARD_IMAP_JUNK_FOLDER`, `PHISHGUARD_IMAP_TRASH_FOLDER` | override preset folder names |
| `PHISHGUARD_BANNER_KEY[_FILE]` | HMAC key that marks PhishGuard's own banner copies |
| `PHISHGUARD_GRAPH_CLIENT_STATE[_FILE]`, `PHISHGUARD_PUBSUB_AUDIENCE`, `PHISHGUARD_PUBSUB_SERVICE_ACCOUNT` | webhook validation |

Every `X` that holds a secret also accepts `X_FILE` (a path, Docker/Kubernetes-secret style).

## What was and wasn't tested

Tested offline in `pytest` (no network): Gmail and Graph through `httpx.MockTransport` fakes that implement paging, history/delta cursors, token endpoints, rate limits and write endpoints; IMAP against a real-socket fake server over TLS with a throwaway certificate; OAuth refresh, rotation, device code, PKCE state check, service-account JWT signing; Pub/Sub JWT verification with locally generated RSA keys.

**Not tested:** any real Google, Microsoft or IMAP account. The fakes were written from the providers' public documentation, and real servers can differ in ways only a real run reveals (error codes, paging edge cases, consent screens, how Graph moves interact with immutable IDs, NetEase/QQ quirks). If you connect a real mailbox, start with `scan_mailbox.py --last 5` before running the worker or any remediation.
