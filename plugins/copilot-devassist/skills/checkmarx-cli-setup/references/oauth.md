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
burns a failed login round-trip. Always ask Question 2 below first, even if a hook's deny message
already shows the `--base-auth-uri <url> --tenant <tenant>` flags as bare placeholders.

**Question 2 — ask in a plain chat message (NOT `AskUserQuestion`)**: the tenant is org-specific
free text with no preset options, and one `AskUserQuestion` cannot return two independent free-text
values. Collect both in a single reply:

> "Browser sign-in it is. Reply with **two things, comma-separated**, in one message — your URL,
> then your tenant:
> 1. **The URL you use to reach Checkmarx One** in your browser — pick your region or paste your own:
>    EU `https://eu.ast.checkmarx.net` · US `https://us.ast.checkmarx.net` · ANZ `https://anz.ast.checkmarx.net` · or your on-prem URL
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

**Invoke cx exactly as the gate's deny message spells it out — do not type a doc-static `cx auth
login`.** On a first-install session `cx` is **not on PATH**, so a **bare** `cx auth login` exits 127
(`command not found`). The auth deny message **embeds the resolved recovery command with cx's absolute
path** (the canonical store — `~/.checkmarx/bin/cx` on Unix, `%LOCALAPPDATA%\Checkmarx\cx\cx.exe` on
Windows — while cx isn't yet on PATH). Take that exact cx invocation and append the two login flags:

**Bash tool (GitHub Copilot CLI (copilot-agent) / macOS / Linux):**
```bash
# Use the resolved cx path from the deny message (bare `cx` works only once it is on PATH):
"$HOME/.checkmarx/bin/cx" auth login --base-auth-uri <your Checkmarx One URL> --tenant <tenant> 1>/dev/null
```

**PowerShell tool (Copilot CLI on Windows):**
```powershell
# Use the & call operator (required for paths with spaces) and $null to suppress stdout:
& "C:/Users/<you>/AppData/Local/Checkmarx/cx/cx.exe" auth login --base-auth-uri <your Checkmarx One URL> --tenant <tenant> 1>$null
```
Replace the path above with the resolved cx path shown in the gate's deny message.
The `&` call operator is mandatory in PowerShell when invoking an executable by absolute path.
Use `1>$null` (not `1>/dev/null`) to suppress the live token on PowerShell.
Run this with the **powershell tool**, not the Bash tool.

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
  the Checkmarx login and MFA there. You have about 5 minutes."*
- Progress text ("Opening browser to…", "Waiting for authentication…") goes to **stderr**, so it
  stays visible; only the secret-bearing stdout is dropped.
- The command **blocks until the developer finishes** (or times out after ~5 minutes). Run it in the
  background or with a timeout of at least 5–6 minutes — do not kill it early.
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
