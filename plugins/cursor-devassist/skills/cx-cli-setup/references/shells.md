# Shell syntax reference (PowerShell · cmd.exe · bash · sh)

The single place that spells out how to write a `cx` command for the shell you are actually in. Every
other skill, rule, and reference in this plugin points here instead of repeating per-shell forms.

**Which shell am I in?** Cursor's Shell tool uses the workspace's default shell: **PowerShell** on
Windows, **bash/zsh** on macOS/Linux. `cmd.exe` appears when the developer has configured it. If a
previous command failed with a parse error, you are almost certainly in a different shell than the
form you used assumed — re-run it using the matching line below.

## The four differences that actually matter

| | PowerShell | cmd.exe | bash / sh |
|---|---|---|---|
| Invoke a **quoted or absolute** path | `& "<path>" args` — the `&` **call operator is required**; without it the quoted path is just a string and PowerShell **prints it instead of running it** | `"<path>" args` | `"<path>" args` |
| Path separators | `\` (backslash) | `\` (backslash) | `/` (forward slash — a `\` is an **escape character**, so a Windows path must be written with `/`) |
| Discard stdout | `1>$null` | `1>NUL` | `1>/dev/null` |
| Environment variable | `$env:LOCALAPPDATA` | `%LOCALAPPDATA%` | `$LOCALAPPDATA` |
| Literal string (no expansion) | `'...'` | *(none — cmd has no literal-quote form; use `"` and escape inner `"` as `\"`)* | `'...'` |

A **bare command name** (`cx auth validate`, `bash "<script>" install`) is identical in all four
shells and needs no call operator and no quoting — prefer it whenever `cx` is on PATH.

## The canonical cx path per shell

On a first-install session `cx` is in the canonical store but **not** on the agent shell's frozen
PATH, so it must be invoked by absolute path:

```powershell
# PowerShell (Windows)
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" auth validate
```

```bat
:: cmd.exe (Windows)
"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" auth validate
```

```bash
# bash / sh — Git Bash on Windows
"$LOCALAPPDATA/Checkmarx/cx/cx.exe" auth validate
# bash / sh — macOS / Linux
"$HOME/.checkmarx/bin/cx" auth validate
```

All of these forms are recognized by the security gate's trusted-setup carve-out, including the
`%VAR%` / `$env:VAR` / `$VAR` / `~` spellings — you do not have to expand the variable yourself.

## Commands that are the same in every shell

- `bash "<plugin-root>/scripts/cx-bootstrap.sh" install` (and `upgrade`) — always written this way,
  in any shell, because `bash` is the program being invoked. Requires Git Bash on Windows.
- Any bare `cx <subcommand>` once cx is on PATH.

## Never chain, substitute, or redirect to a file

While the gate is blocking (cx missing / outdated / unauthenticated) only **bare, single** commands
reach cx. Do **not** use `;`, `&&`, `||`, `|`, backticks, `$(...)`, `^` (cmd escape), or a redirect to
a real file — a chained probe is blocked as a whole and never runs. Run each check as its own
command. The **only** permitted redirect is stdout suppression to the null device (the third row
above), which exists so `cx auth login` cannot leak its token.

## JSON arguments

`cx ignore-vulnerability --data <json>` takes a JSON document as one argument, and JSON is full of
double quotes. **Do not use the single-quote form here even on PowerShell / bash**, even though
that's the normal literal-string convention for those shells: Cursor's own command-execution layer
can reformat a single-quoted argument into a double-quoted one before the real shell runs it
(observed on Windows), which strips the embedded `"` around the JSON keys and sends `cx` invalid
JSON (`{FileName:...}` instead of `{"FileName":...}` — the `'F' looking for beginning of object key
string` error). Always double-quote the whole value and escape every inner `"` yourself, the same
way on every shell:

```powershell
# PowerShell — double-quote the whole value, double each inner "
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" ignore-vulnerability --scan-type sca --data "{""packageName"":""lodash""}"
```

```bat
:: cmd.exe — double-quote the whole value, double each inner "
"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" ignore-vulnerability --scan-type sca --data "{""packageName"":""lodash""}"
```

```bash
# bash / sh — double-quote the whole value, backslash-escape each inner "
"$HOME/.checkmarx/bin/cx" ignore-vulnerability --scan-type sca --data "{\"packageName\":\"lodash\"}"
```

### @file syntax (preferred when inline JSON still fails)

Write the finding JSON to a file under `.checkmarx/`, then pass it with `@file` — this avoids
Cursor's inline-JSON quoting layer entirely. Use **native Windows paths** for `--data` and
`--ignored-file-path` (`c:\project\.checkmarx\finding.json`), never MSYS `/c:/…` spellings — cx's
Go runtime cannot open `/c:/…` on Windows.

Prep (each as its own Shell command — `| Out-Null` on `New-Item` is allowed by the gate):

```powershell
New-Item -ItemType Directory -Force -Path "c:\project\.checkmarx" | Out-Null
Set-Content -Path "c:\project\.checkmarx\finding.json" -Value '{"FileName":"Demo.java","Line":5,"RuleID":1027}' -NoNewline
```

Then ignore (one bare command):

```powershell
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" ignore-vulnerability --scan-type asca --data "@c:\project\.checkmarx\finding.json" --ignored-file-path "c:\project\.checkmarx\checkmarxIgnoredTempList.json"
```

After a successful ignore, **retry the original Write/StrReplace once** — the write hook runs a
separate scan and only honors findings recorded in the ignore list. Then **delete the prep file**
you wrote for the `@file` workaround (`finding.json`, and the `.checkmarx/` directory if it is now
empty) — do not remove files created by the ignore command itself (e.g. `checkmarxIgnoredTempList.json`).

## Manual Windows install without Git Bash

`references/manual-install.md` uses a Git Bash block. The PowerShell equivalent, for a machine where
Git Bash is not yet installed (install it anyway — the gate launches through `sh`):

```powershell
$store = "$env:LOCALAPPDATA\Checkmarx\cx"
New-Item -ItemType Directory -Force -Path $store | Out-Null
Invoke-WebRequest -Uri "https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_windows_x64.zip" -OutFile "$env:TEMP\cx-cli.zip"
Expand-Archive -Path "$env:TEMP\cx-cli.zip" -DestinationPath $store -Force
Remove-Item "$env:TEMP\cx-cli.zip"
```

These are multi-statement setup commands, not `cx` commands, so run them in a terminal yourself rather
than through the gated Shell tool — the gate only admits **bare, single** commands while it is blocking.

## Paths containing spaces

Always quote a path, in every shell — `"C:\Users\Jane Doe\..."` / `"/Users/Jane Doe/..."`. In
PowerShell a quoted path additionally needs the `&` call operator (first row above); that is the one
place where quoting alone is not enough.

## Deny messages already do this for you

When a Checkmarx hook denies an action, its `agent_message` / `additional_context` embeds the recovery
command **already rendered for each shell**, with the detected shell listed first:

```
Run the line for YOUR shell (all forms are equivalent and all are allowed by the gate):
    PowerShell: & "C:\Users\me\AppData\Local\Checkmarx\cx\cx.exe" auth validate
    bash / sh:  "C:/Users/me/AppData/Local/Checkmarx/cx/cx.exe" auth validate
    cmd.exe:    "C:\Users\me\AppData\Local\Checkmarx\cx\cx.exe" auth validate
```

Copy the line matching your shell **verbatim** — do not retype it, translate it, or substitute
`${CURSOR_PLUGIN_ROOT}` (that variable is empty in the agent's shell).
