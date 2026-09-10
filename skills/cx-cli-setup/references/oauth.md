# Path B — Browser sign-in (`cx auth login`)

The browser flow opens the Checkmarx One login page, the developer logs in (with MFA), and the
CLI saves the resulting OAuth refresh token as `cx_apikey` automatically. On a fresh setup there
is no stored config to derive from, so collect the **URL + tenant** first — as Question 2, in one
step.

> **Prerequisite:** Path B is offered only when `cx auth login` exists in this build (the
> capability check in Phase 2: `login` listed under `cx auth --help`). If it is not listed, use
> Path A (API key).

**Never guess or default the URL or tenant** (e.g. do not try an assumed tenant like `checkmarx` or
a guessed host like `https://iam.checkmarx.net`) — both are org-specific and a wrong guess just
burns a failed login round-trip.

**First check whether the values are already provided — if so, SKIP Question 2:**
- If the gate's deny recovery command already shows a **real** `--base-auth-uri <URL> --tenant
  <tenant>` (concrete values, not the literal `<url>` / `<tenant>` placeholders), your administrator
  preconfigured them in the plugin's `config/cx-onboarding.properties`. Use those values as-is: go
  straight to running that login command and do **not** ask Question 2.
- If the deny message lists **numbered environments** from an earlier `cx auth login` on this machine,
  present them in chat and ask the developer to pick **one** (or supply a different URL + tenant).
  Run only the command for the environment they choose — never auto-pick.
- Only when the flags are still **bare placeholders** (`<url>` / `<tenant>`) do you ask Question 2
  below.

**Question 2 — ask in a plain chat message**: collect URL and tenant in a single reply (both are
org-specific free text):

> "Browser sign-in it is. Reply with **two things, comma-separated**, in one message — your URL,
> then your tenant:
> 1. **The URL you use to reach Checkmarx One** in your browser — pick your region or paste your own:
>    US `https://ast.checkmarx.net` · US2 `https://us.ast.checkmarx.net` · EU `https://eu.ast.checkmarx.net` · EU2 `https://eu-2.ast.checkmarx.net` · ANZ `https://anz.ast.checkmarx.net` · India `https://ind.ast.checkmarx.net` · or your on-prem URL
>    (full region list + how to find your tenant: https://docs.checkmarx.com/en/34965-68530-logging-in-to-checkmarx-one.html)
> 2. **Your tenant** — the Checkmarx One organization you sign in under.
>
> Example: `https://eu.ast.checkmarx.net, acme-corp`
> (Don't know them? The **URL** is what's in the browser address bar on Checkmarx One; the
> **tenant** is shown in Settings → your organization. Or pick **API key** instead — it needs neither.)"

Derive the two flags from the reply:
- **URL** → `--base-auth-uri`. Normalize to scheme+host only — strip any path, query, and trailing
  slash (`https://eu.ast.checkmarx.net/auth/` → `https://eu.ast.checkmarx.net`); prepend `https://`
  if the scheme is missing. The developer never needs the IAM/auth host: `cx` follows the app host's
  `/auth` redirect to IAM during OIDC discovery (cloud and on-prem).
- **Tenant** → `--tenant`, passed verbatim.

Keep it to **two questions total** — never split into a third turn. If the reply has only one
value or no URL token, re-show the same combined prompt once. If `cx auth login` later fails with
*"realm not found — check --tenant and --base-auth-uri"* (a rare deployment that doesn't redirect
`/auth` to IAM), fall back to Path A.

**Run the login command (both flags required on every login).** The CLI does not persist these and
(by design) ignores the realm embedded in any stored token, so omitting `--base-auth-uri` fails with
a "missing URI" error and omitting `--tenant` fails with "please provide tenant". Run it with stdout
discarded (see the security note).

**Run the login command via `run_shell_command` (Gemini CLI's shell tool).** On a first-install
session `cx` is **not on PATH**, so a **bare** `cx auth login` exits 127 (`command not found`).
The auth deny message **embeds the resolved recovery command with cx's absolute path** (the canonical
store — `~/.checkmarx/bin/cx` on Unix, `%LOCALAPPDATA%\Checkmarx\cx\cx.exe` on Windows — while cx
isn't yet on PATH). Copy that exact command from the deny message:

**Unix / macOS / Linux** (`run_shell_command`):
```bash
"$HOME/.checkmarx/bin/cx" auth login --base-auth-uri <your Checkmarx One URL> --tenant <tenant> 1>/dev/null
```

**Windows** (`run_shell_command` — Gemini CLI runs via PowerShell):
```powershell
& "C:/Users/<you>/AppData/Local/Checkmarx/cx/cx.exe" auth login --base-auth-uri <your Checkmarx One URL> --tenant <tenant> 1>$null
```
Replace the path above with the resolved cx path shown in the gate's deny message.
On Windows the `&` call operator is mandatory when invoking an executable by absolute path.
Use `1>$null` (not `1>/dev/null`) to suppress the live token on PowerShell.

**Run this YOURSELF — do NOT hand it to the developer with the `!` prefix.** This
is the OAuth path: the agent runs the resolved login command itself (unlike an API key, which the
*developer* sets because it is a plaintext secret). The security gate's auth-recovery carve-out admits
`cx auth …` / `cx configure …` commands — including the resolved absolute-path form and the PowerShell
`& "abs-path" auth …` form the deny message hands you — through even while it is blocking every other
action (that is exactly why the carve-out exists), so you never need `!` here. The browser opens
automatically on the developer's machine; they only complete the login there. If an earlier tool call
was denied by the gate, that does NOT mean the resolved `cx auth login` will be — the recovery commands
are allowed; run it.

- The default browser opens automatically. Tell the developer: *"Your browser is opening — complete
  the Checkmarx login and MFA there. This command waits until you finish (about 5 minutes)."*
- **Do not ask them to reply "done" / "logged in".** `cx auth login` **blocks until the browser
  flow finishes** (or times out after ~5 minutes). When the tool call returns, go straight to
  Phase 3 (`cx auth validate`) yourself.
- **Run it in the foreground** with a `run_shell_command` timeout of **at least 6 minutes**
  (`timeout: 360000` or the client's equivalent). Do **not** background it — a backgrounded login
  returns immediately, which is what makes the agent stop and wait for a chat reply.
- Progress text ("Opening browser to…", "Waiting for authentication…") goes to **stderr**, so it
  stays visible; only the secret-bearing stdout is dropped.
- Headless / SSH (no browser): add `--no-browser`; the CLI prints the authorize URL to stderr.
- On the redirect to `http://localhost:<port>/checkmarx1/callback` the token is saved as
  `cx_apikey`. Confirm success with `cx auth validate` (Phase 3) — do not read the login output.

> **Security — never capture the token.** In default mode `cx auth login` prints
> `CX_APIKEY=<token>` (a live refresh token) to **stdout** for scripting parity. Discard **stdout
> only**, using the shell's null device — bash/zsh/Git Bash `1>/dev/null`, PowerShell `1>$null`,
> cmd `1>NUL` — and leave stderr attached. The token is still written to the cx config on disk
> (`~/.checkmarx/checkmarxcli.yaml`, the `cx_apikey` field), which is where every `cx` command and
> the bundled remediation MCP read it from. Treat the login as fire-and-forget: never echo, capture,
> or store the token's value, and do not use `--session local`/`global` (they change where the token
> is emitted).

> **Token rotation.** Every `cx auth login` revokes the previous refresh token before issuing a new
> one, so re-authenticating with the same flags is always safe. The remediation MCP reads the
> credential live from cx config and picks up the rotated token automatically, with no re-register
> step. For long-lived or unattended use, prefer Path A (a long-lived API key needs no refresh).

**Protect the credential file.** After auth succeeds, note: the credential is stored in plaintext in
`~/.checkmarx/checkmarxcli.yaml` (Windows: `%USERPROFILE%\.checkmarx\checkmarxcli.yaml`). Protect it
like an SSH private key — restrict permissions (`chmod 600 ~/.checkmarx/checkmarxcli.yaml` on
macOS/Linux) and exclude it from backups and version control.

## Re-authentication (Path B)

When credentials expired and the developer originally used browser sign-in, re-run the **same**
`cx auth login --base-auth-uri <URL> --tenant <tenant>` command (both flags every time; stdout
discarded; never capture the token). If a gate deny message triggered the re-auth, use the resolved
cx invocation it embeds (absolute path while cx isn't on PATH) rather than a bare `cx`. No MCP action
is needed — the bundled remediation MCP re-reads the credential from cx config on its next call.
