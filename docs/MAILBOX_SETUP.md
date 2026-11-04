# Connecting a real mailbox

This guide connects PhishGuard to Gmail, Microsoft 365 / Outlook.com, or any IMAP mailbox (iCloud, Yahoo, Fastmail, QQ Mail, 163, Zoho, ...), step by step. You need about 15 minutes per provider.

> **Status:** the connectors were developed and tested against faithful fakes of each provider's API (see `tests/fakes.py`), not against live accounts. The first time you connect a real mailbox, start in **read-only mode** (the default) with `scripts/scan_mailbox.py`, and only then consider remediation. If something differs from these steps, the provider's own console wins; please open an issue.

## 0. What PhishGuard will and won't do

- **Reading** uses the narrowest permission each provider offers: Gmail `gmail.readonly`, Microsoft Graph `Mail.Read`. IMAP opens the inbox read-only (`EXAMINE`) and fetches with `BODY.PEEK[]`, so not even the "read" flag changes.
- **Changing mail** (quarantine, label, warning banner) is off by default. It needs a *second*, separate credential with write permission (`gmail.modify`, `Mail.ReadWrite`), and every change goes through PhishGuard's MFA gateway. Deleting or restoring mail, and bulk actions, always ask a human for an MFA code.
- **Secrets** are only read from environment variables or files you create outside the repository with `chmod 600`. Tokens PhishGuard stores are written with mode 0600. Nothing secret is printed or logged.

Install once:

```bash
pip install -r requirements.txt
mkdir -p ~/.config/phishguard/tokens && chmod 700 ~/.config/phishguard ~/.config/phishguard/tokens
```

---

## 1. Gmail (personal account)

### 1.1 Create an OAuth client in Google Cloud

1. Open <https://console.cloud.google.com/> and create a project (top bar → project picker → **New project**), e.g. `phishguard`.
2. **APIs & Services → Library** → search **Gmail API** → **Enable**.
3. **APIs & Services → OAuth consent screen** (called *Google Auth Platform → Branding/Audience* in newer consoles):
   - User type **External** (or **Internal** if you are on Google Workspace and only scan your own domain).
   - App name `PhishGuard`, your email as support and developer contact.
   - **Scopes**: add `https://www.googleapis.com/auth/gmail.readonly`. Add `https://www.googleapis.com/auth/gmail.modify` only if you will enable remediation.
   - **Test users** (Audience): add the Gmail address you want to scan.
4. **APIs & Services → Credentials → Create credentials → OAuth client ID** → Application type **Desktop app** → **Create** → **Download JSON**.
5. Save it outside the repo and lock it down:

   ```bash
   mv ~/Downloads/client_secret_*.json ~/.config/phishguard/google-client.json
   chmod 600 ~/.config/phishguard/google-client.json
   ```

> While the consent screen is in **Testing**, Google expires refresh tokens after **7 days**. For your own account you can either re-run the authorization weekly or switch the app to **In production**; Google then shows an "unverified app" screen that you can click through for your own account. `gmail.readonly` and `gmail.modify` are *restricted* scopes: letting other people use your client requires Google's verification.

### 1.2 Authorize (once) and scan

```bash
python scripts/scan_mailbox.py --provider gmail \
  --client-file ~/.config/phishguard/google-client.json \
  --token-file ~/.config/phishguard/tokens/gmail-read.json --authorize
```

A browser opens. Sign in, allow **read** access, and the refresh token is saved to `gmail-read.json` (mode 0600). On a machine without a browser, add `--no-browser`, open the printed URL elsewhere, and make sure the redirect reaches `http://127.0.0.1:<port>` on the machine running the command (for example via `ssh -L`).

```bash
python scripts/scan_mailbox.py --provider gmail \
  --client-file ~/.config/phishguard/google-client.json \
  --token-file ~/.config/phishguard/tokens/gmail-read.json --last 20
```

Output: one line per message with the verdict (`PHISH` / `ok` / `TOO_LARGE` / `UNPARSEABLE`), the risk score, the top reasons, and the sender and subject (`--redact` hides them; `--json` for machines).

## 2. Google Workspace (whole domain, admin)

A service account with **domain-wide delegation** can read the mailboxes you name, without each user signing in.

1. In the Cloud project above: **IAM & Admin → Service accounts → Create service account** (no roles needed).
2. Open it → **Keys → Add key → JSON** → save as `~/.config/phishguard/workspace-sa.json`, `chmod 600`. (If your organization blocks key creation, the policy `iam.disableServiceAccountKeyCreation` must be relaxed for this project.)
3. Copy the service account's **Unique ID** (a number).
4. In the Workspace Admin console (<https://admin.google.com>): **Security → Access and data control → API controls → Manage Domain Wide Delegation → Add new**. Client ID = that number. OAuth scopes = `https://www.googleapis.com/auth/gmail.readonly` (add `https://www.googleapis.com/auth/gmail.modify` only for remediation).
5. Scan one user's mailbox:

   ```bash
   python scripts/scan_mailbox.py --provider gmail \
     --service-account-key ~/.config/phishguard/workspace-sa.json --subject alice@example.com --last 20
   ```

Delegation is powerful: the key can read every mailbox in the domain for the granted scopes. Keep the key file private and rotate it.

## 3. Microsoft 365 / Outlook.com (Microsoft Graph)

### 3.1 Register an app (once)

1. Open <https://entra.microsoft.com> → **Applications → App registrations → New registration**.
   - Name `PhishGuard`.
   - **Supported account types**: *Accounts in any organizational directory and personal Microsoft accounts* if you want Outlook.com/Hotmail; *this organizational directory only* for a single company.
   - Redirect URI: leave empty.
2. On the app's **Overview** page, copy the **Application (client) ID** and the **Directory (tenant) ID**.
3. **Authentication → Advanced settings → Allow public client flows → Yes** → Save. (Needed for the device-code sign-in.)
4. **API permissions → Add a permission → Microsoft Graph → Delegated permissions** → `Mail.Read` and `offline_access` → Add. (For remediation add `Mail.ReadWrite` as well, used only by the write credential.)

### 3.2 Sign in (once) and scan

`--tenant`: `common` (work + personal accounts), `consumers` (Outlook.com only), or your tenant ID.

```bash
python scripts/scan_mailbox.py --provider graph --tenant common --client-id <application-id> \
  --token-file ~/.config/phishguard/tokens/o365-read.json --authorize
```

It prints a short code and the URL `https://microsoft.com/devicelogin`. Open it on any device, enter the code, sign in, and accept. The refresh token is saved (mode 0600).

```bash
python scripts/scan_mailbox.py --provider graph --tenant common --client-id <application-id> \
  --token-file ~/.config/phishguard/tokens/o365-read.json --last 20
```

### 3.3 Organization-wide (app-only, admin)

For a service that reads shared or many mailboxes without anyone signing in:

1. Same app → **API permissions → Add → Microsoft Graph → Application permissions → `Mail.Read`** → **Grant admin consent**.
2. **Certificates & secrets → New client secret** → copy the value once and keep it in an environment variable or a private file.
3. **Limit the app to the mailboxes it needs.** An application `Mail.Read` grant can otherwise read *every* mailbox in the tenant. Use Exchange Online's application access policies or RBAC for Applications to scope it to a mail-enabled security group.
4. Scan (app-only tokens have no "me": name the mailbox):

   ```bash
   export PG_GRAPH_CLIENT_SECRET='<secret value>'
   python scripts/scan_mailbox.py --provider graph --tenant <tenant-id> --client-id <application-id> \
     --client-secret-env PG_GRAPH_CLIENT_SECRET --user security@contoso.com --last 20
   ```

## 4. Any IMAP mailbox (iCloud, Yahoo, Fastmail, QQ, 163, Zoho, ...)

IMAP needs an **app password** (a separate password the provider generates for mail apps), never your main account password. PhishGuard connects only over TLS (port 993) and verifies the server certificate. Providers rename their settings menus from time to time; if a path below doesn't match, search the provider's help for "app password" (or "授权码").

| `--preset` | Server | How to get the password |
|---|---|---|
| `icloud` | imap.mail.me.com | <https://account.apple.com> → Sign-In and Security → App-Specific Passwords. Apple's docs give the part of your address before `@` as the user name. |
| `yahoo` | imap.mail.yahoo.com | Account Info → Account Security → Generate app password |
| `aol` | imap.aol.com | Account Security → Generate app password |
| `fastmail` | imap.fastmail.com | Settings → Privacy & Security → app passwords |
| `zoho` | imap.zoho.com (`.eu` / `.in` for those regions: use `--host`) | Enable IMAP in Mail settings; with 2FA create an app-specific password |
| `qq` | imap.qq.com | QQ Mail → Settings → Account → enable IMAP/SMTP → generate the authorization code (授权码) |
| `163` / `126` | imap.163.com / imap.126.com | Settings → POP3/SMTP/IMAP → enable IMAP → set the client authorization code (授权码). PhishGuard sends the IMAP ID command NetEase requires. |
| `yandex` | imap.yandex.com | Enable IMAP in mail settings; create an app password |
| `gmail` | imap.gmail.com | Prefer section 1. IMAP: app password (requires 2-Step Verification) or `--oauth google` |
| `outlook` | outlook.office365.com | Prefer section 3. Passwords no longer work; `--oauth microsoft` (needs the `IMAP.AccessAsUser.All` delegated permission) |

```bash
read -rs PG_IMAP_PASSWORD && export PG_IMAP_PASSWORD     # type the app password; nothing is echoed
python scripts/scan_mailbox.py --provider imap --preset icloud --username you \
  --password-env PG_IMAP_PASSWORD --last 20
```

Or keep it in a file: `install -m 600 /dev/null ~/.config/phishguard/icloud.pass`, paste the password into it, and pass `--password-file ~/.config/phishguard/icloud.pass`.

IMAP has no read-only permission: an app password can always change mail. PhishGuard's read path still never does (EXAMINE + PEEK, enforced in tests), but the credential itself is as powerful as the mailbox. Revoke it when you stop using PhishGuard.

## 5. Run continuously

1. `cp examples/mailboxes.example.yaml ~/.config/phishguard/mailboxes.yaml`, keep the mailboxes you set up, and delete the rest. The file contains no secrets, only `*_env` / `*_file` pointers.
2. Try one pass without changing anything:

   ```bash
   python -m phishguard.worker --config ~/.config/phishguard/mailboxes.yaml --once --dry-run
   ```

3. Run it in a loop (every `interval_seconds`, default 300):

   ```bash
   python -m phishguard.worker --config ~/.config/phishguard/mailboxes.yaml
   ```

   Example systemd user unit, `~/.config/systemd/user/phishguard-worker.service`:

   ```ini
   [Service]
   ExecStart=/usr/bin/python3 -m phishguard.worker --config %h/.config/phishguard/mailboxes.yaml
   WorkingDirectory=%h/phishguard
   # chmod 600; holds the PG_* secrets referenced by *_env in mailboxes.yaml
   EnvironmentFile=%h/.config/phishguard/env
   Restart=on-failure
   [Install]
   WantedBy=default.target
   ```

The worker remembers what it has scanned (`state_db`), so restarts never rescan or double-act. When a provider rate-limits it, it waits as long as the provider asks.

## 6. Turn on remediation (optional)

1. Create a **write** credential, separate from the read one:
   - Gmail: the consent screen must include `gmail.modify`; then
     `python scripts/scan_mailbox.py --provider gmail --client-file ... --token-file ~/.config/phishguard/tokens/gmail-write.json --authorize --write`
   - Microsoft: add `Mail.ReadWrite` (delegated, or application with admin consent); then the same `--authorize --write` with a different `--token-file`.
   - IMAP: the same app password (IMAP has no scopes).
2. In `mailboxes.yaml`, set `remediation.enabled: true`, choose `action` (`quarantine`, `label` or `banner`) and `min_risk`, and point `remediation.auth` at the write token file.
3. What happens: a flagged message gets one automatic action, recorded in the audit log. Quarantine moves it out of the inbox (Gmail label `PhishGuard/Quarantine`, Outlook *Junk Email*, IMAP `Junk`). Banner adds a warned copy to the inbox and quarantines the original (Gmail and IMAP; Outlook can't edit received mail, so use `label`). Nothing is ever deleted automatically.
4. Restore, delete, or act on more than 10 messages at once by hand, with an MFA code:

   ```bash
   python scripts/mailbox_action.py --config ~/.config/phishguard/mailboxes.yaml --mailbox personal-gmail \
     --as alice restore --ids <message-id>
   ```

   Enroll an authenticator first (`POST /mfa/enroll` with an admin key); otherwise the development code channel prints the code on the console.

## 7. Push notifications instead of polling (optional, advanced)

Polling every few minutes is enough for most people. Push makes the worker scan within seconds. It needs a public HTTPS URL for the PhishGuard API, the `webhooks` section in `mailboxes.yaml`, and `PHISHGUARD_MAILBOX_CONFIG` pointing at that file for both the API and the worker.

- **Microsoft Graph:** pick a random client state (`export PG_GRAPH_CLIENT_STATE=$(python -c 'import secrets;print(secrets.token_urlsafe(32))')`), then
  `python scripts/scan_mailbox.py --config ~/.config/phishguard/mailboxes.yaml --mailbox work-o365 --graph-subscribe https://<host>/webhooks/graph --client-state-env PG_GRAPH_CLIENT_STATE`.
  Graph calls the URL with a validation token first; PhishGuard echoes it. Subscriptions expire after about 3 days: re-run the command daily (cron/systemd timer).
- **Gmail:** in Google Cloud create a Pub/Sub **topic**; grant `gmail-api-push@system.gserviceaccount.com` the **Pub/Sub Publisher** role on it; create a **push subscription** to `https://<host>/webhooks/gmail` with **authentication enabled** (a service account you create; put its email in `webhooks.gmail.service_account` and the push URL in `audience`). Then
  `python scripts/scan_mailbox.py --config ... --mailbox personal-gmail --gmail-watch projects/<project>/topics/<topic>` and renew it at least weekly.

A notification never contains mail and is only a hint to scan sooner, so a lost or forged one can't make PhishGuard skip or change anything.

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `no refresh token ... run the --authorize flow first` | Authorize with the same `--token-file` |
| Gmail works for 7 days, then `token endpoint ... invalid_grant` | Consent screen in Testing: re-authorize or publish (section 1.1) |
| Graph `AADSTS7000218` during device sign-in | "Allow public client flows" is off (3.1 step 3) |
| Graph app-only `HTTP 403 ErrorAccessDenied` | Admin consent missing, or the mailbox is outside the app's access policy |
| IMAP `login ... failed` | Wrong user name format or not an app password; IMAP disabled in the provider's settings |
| `refusing secret/token file inside the repository` | Move the file under `~/.config/phishguard/` |
| `... is readable by group/others; run: chmod 600` | Exactly that |
| `provider asked to wait 3600s` | Rate limit: the worker pauses that mailbox and retries later |
