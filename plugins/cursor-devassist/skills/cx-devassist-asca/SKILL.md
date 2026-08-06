---
name: cx-devassist-asca
description: "Runs a Checkmarx ASCA (AI Security Code Assistant) SAST scan on a SOURCE CODE file to detect code vulnerabilities, and remediates findings using the Checkmarx MCP tool. Use when a user asks to scan or fix a source code file (.py/.js/.java/.go/.ts/…) for security vulnerabilities. For dependency manifests/lockfiles (package.json, requirements.txt, go.mod, …) use cx-devassist-sca instead. Invoke as: /cx-devassist-asca"
---

# CX Security ASCA

Detects and remediates SAST vulnerabilities in source files using Checkmarx ASCA.

## When to Use

This skill has two entry points:

1. **On-demand scan** — User asks to scan a **source code file** for vulnerabilities (e.g., "scan this
   file", "check app.py for security issues"). If the target is a **dependency manifest/lockfile**
   (package.json, requirements.txt, go.mod, …), use `cx-devassist-sca` instead.
2. **Remediation** — User asks to fix ASCA findings, the agent receives a **hook deny** on Write/StrReplace (`agent_message` / `CHECKMARX_HOOK_DENY`), or ASCA findings are surfaced via the stop hook's `followup_message`.

> **If ASCA findings are already present in context** (hook deny `agent_message`, `CHECKMARX_HOOK_DENY` block, prior scan result, or stop-hook message), **skip Flow 1 entirely** and proceed directly to Flow 2. Do not retry the blocked write, paste code in chat, or use shell workarounds.

### Routing — which Checkmarx capability to use

Pick by the target, and ask if it is ambiguous:

| The user wants to scan… | Use |
|---|---|
| A **source code file** (`.py`, `.js`, `.java`, `.go`, `.ts`, …) for code vulnerabilities | **this skill** (SAST/ASCA) |
| A **dependency manifest / lockfile** (package.json, requirements.txt, go.mod, pom.xml, …) | `cx-devassist-sca` (SCA/OSS) |
| An **entire project / repository** at cloud scale, or existing platform scan results | the Checkmarx MCP (Cx1 cloud) tools |

A bare "scan this file" refers to whatever file is in context: source code → this skill; a
manifest/lockfile → `cx-devassist-sca`. If it is unclear which, ask the user.

## Prerequisites

- Checkmarx `cx` CLI installed. On a first-install session `cx` is in the **canonical store** but not
  yet on the agent shell's PATH, so invoke it by its **absolute path**, written for the shell you are
  actually in — PowerShell needs the `&` call operator and `$env:` variables, cmd needs `%VAR%`, bash
  needs forward slashes. All four forms are in
  [`../cx-cli-setup/references/shells.md`](../cx-cli-setup/references/shells.md); the short version is:

  ```bash
  "$HOME/.checkmarx/bin/cx"                       # bash / sh (macOS, Linux)
  "$LOCALAPPDATA/Checkmarx/cx/cx.exe"             # bash / sh (Git Bash on Windows)
  & "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe"       # PowerShell — & is REQUIRED
  "%LOCALAPPDATA%\Checkmarx\cx\cx.exe"            # cmd.exe
  ```

  Fall back to a bare `cx` (identical in every shell) only when it is already on PATH.
- Checkmarx MCP server connected (required for remediation).

> **Remediation is MCP-only.** Every fix MUST come from `mcp__Checkmarx__codeRemediation`. If that tool
> is not available, you MUST NOT remediate by any other means — no manual edits, no generic or
> LLM-generated fixes, and do not apply the `remediationAdvise` text yourself. Stop and recover the MCP
> first (see Flow 2 → Step 2, "If the tool is not available").

---

## Flow 1: On-Demand Scan

### Step 1 — Identify Files to Scan

Ask the user which file(s) to scan if not already specified.

### Step 2 — Run the ASCA Scan

Run the scan on each file. Invoke cx by its canonical absolute path so it resolves even when cx isn't
on the agent shell's PATH (a first-install session); use a bare `cx` only when cx is already on PATH:

```bash
# bash / sh (macOS, Linux):
"$HOME/.checkmarx/bin/cx" scan asca -s "<file-path>"
# bash / sh (Git Bash on Windows):
"$LOCALAPPDATA/Checkmarx/cx/cx.exe" scan asca -s "<file-path>"
```

```powershell
# PowerShell (Cursor's default shell on Windows) - the & call operator is REQUIRED
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan asca -s "<file-path>"
```

```bat
:: cmd.exe
"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" scan asca -s "<file-path>"
```

### Step 3 — Process Results

The scan returns a JSON response:

```json
{
  "request_id": "<uuid>",
  "status": true,
  "message": "Scan successful",
  "scan_details": [
    {
      "rule_id": 4059,
      "language": "Python",
      "rule_name": "Unsafe use of 'shell=True' in subprocess without 'shlex.quote'",
      "severity": "High",
      "file_name": "example.py",
      "line": 38,
      "problematicLine": "<the offending line of code>",
      "length": 155,
      "remediationAdvise": "<how to fix it>",
      "description": "<explanation of the vulnerability>"
    }
  ]
}
```

- **If `scan_details` is empty** — Inform the user the file passed the ASCA security scan with no findings.
- **If `scan_details` has findings** — Report each finding:
  - `rule_name` — vulnerability type
  - `severity` — Critical / High / Medium / Low
  - `file_name` and `line` — location
  - `description` — what the vulnerability is
  - `remediationAdvise` — how to fix it

  Then ask the user: **"Would you like me to remediate these findings?"**
  If yes, proceed to the Remediation flow below.

---

## Flow 2: Remediation

Triggered either after the user confirms in Flow 1, or when SAST vulnerabilities detected by ASCA need to be fixed.

Perform all steps **completely and autonomously** — no user interaction.

### Step 1 — Detect Language

Determine the programming language of the affected file. If unknown, leave `language` empty.

### Step 2 — Call `mcp__Checkmarx__codeRemediation`

For each finding, call the `mcp__Checkmarx__codeRemediation` tool:

```json
{
  "language": "[auto-detected programming language]",
  "metadata": {
    "ruleId": "[rule_name from scan]",
    "description": "[description from scan]",
    "remediationAdvice": "[remediationAdvise from scan]"
  },
  "type": "sast"
}
```

- If the tool is **available**: parse `remediation_steps` from the response and proceed to Step 3.
- If the tool is **not available**: **STOP. Do NOT remediate by any other means** — no manual fix, no
  generic fix, and do not apply the `remediationAdvise` text yourself. Leave the finding **unfixed**
  (do not write or edit any code). Then recover the MCP:

  1. The plugin **declares this MCP in `mcp.json`**, so it loads automatically when the plugin is
     installed under `~/.cursor/plugins/local/`. If the tool is missing, the usual cause is that cx is
     not configured/authenticated — the bridge can't derive the URL or auth header without a valid key.
     Verify with `cx auth validate` — bare when cx is on PATH, otherwise by its canonical absolute
     path in **your shell's** form (`../cx-cli-setup/references/shells.md`):
     `"$HOME/.checkmarx/bin/cx" auth validate` (bash/sh on Unix),
     `& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" auth validate` (PowerShell),
     `"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" auth validate` (cmd.exe). If it fails (or reports no API
     key), run `/cx-cli-setup`.
  2. Then tell the user the **one** step only they can perform — Cursor loads a plugin's MCP servers
     at startup, so the server can't become live in this running session on its own:

     > "The Checkmarx remediation MCP isn't connected in this session. Please run **Developer: Reload
     > Window** (Command Palette) to reload it, then check that `Checkmarx` shows connected in your MCP
     > settings — then ask me to remediate again. I won't apply a non-Checkmarx fix in the meantime."

  Then end the remediation flow without modifying any code.

### Step 3 — Apply the Fix

- Execute each instruction in `remediation_steps` in order.
- **Only modify code at or around the problematic line** (`line` from scan results) — do not touch unrelated code.
- For each change, track:
  - File modified
  - Line number
  - Type of change (e.g., input validation, sanitization, secure API usage)
  - Before → after values

### Step 4 — Re-scan

After all fixes are applied, re-run (same canonical absolute-path invocation as Flow 1 Step 2;
bare `cx` only when it is on PATH):

```bash
# bash / sh (macOS, Linux):
"$HOME/.checkmarx/bin/cx" scan asca -s "<file-path>"
# bash / sh (Git Bash on Windows):
"$LOCALAPPDATA/Checkmarx/cx/cx.exe" scan asca -s "<file-path>"
```

```powershell
# PowerShell (Cursor's default shell on Windows) - the & call operator is REQUIRED
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan asca -s "<file-path>"
```

```bat
:: cmd.exe
"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" scan asca -s "<file-path>"
```

The scan reads the WHOLE file, so it also reports findings in code you never touched. **Remediate only
the findings that belong to your own changes** — everything else is pre-existing and out of scope.

Classify every entry in `scan_details` against the changes you tracked in Step 3:

- **In scope — remediate.** Either:
  - the finding you set out to fix is still there (same `rule_id`, at or near its original line) — your
    fix did not resolve it; or
  - the finding sits on a line you added or modified — your fix introduced it.
- **Out of scope — do NOT fix, and do not edit that code.** Every other finding: it lives in code you
  did not touch and was already there before you started.

Match on `problematicLine` (the offending source text) rather than the line number alone: if your fix
added or removed lines, every finding below the edit shifts by that many lines, and a number-only match
mis-classifies them as new.

Repeat Flow 2 from Step 2 for the in-scope findings **only**. If an in-scope finding survives a second
remediation attempt, stop and report it unresolved — do not keep looping.

Report the out-of-scope findings in the Step 5 summary as pre-existing and unfixed; leave their code
alone.

### Step 5 — Output Remediation Summary

```
Remediation Summary

Rule:             [rule_name]
Severity:         [severity]
Issue Type:       SAST Security Vulnerability
Problematic Line: [line]

Files Modified:
1. [file]
   - Line [n]: [description of change]
   - [additional changes]

Pre-existing findings (NOT fixed — outside the scope of this remediation):
- [rule_name] — line [n] — [severity]
- (omit this section entirely when the re-scan reports none)
```

**Final status:**
- ✅ All fixed: "Remediation completed for security rule [rule_name]. Build status: PASS. Security tests: PASS."
- ⚠️ Partially fixed: "Remediation partially completed — manual review required. TODOs inserted where applicable."
- ❌ Failed: "Remediation failed for security rule [rule_name]. Reason: [summary]. Unresolved issues listed above."

### Suppression (only when explicitly requested and confirmed as a false positive)

If the user decides to suppress a finding rather than fix it (e.g. after a hook deny on
Write/StrReplace, per `rules/cx-hook-deny.mdc`'s "If suppress" step), use `cx ignore-vulnerability`
rather than a manual edit or a shell workaround. The finding shape for ASCA is:

```json
{"FileName": "<file_name from scan>", "Line": <line from scan>, "RuleID": <rule_id from scan>}
```

The `--data` value is a JSON document, so it is full of double quotes. **Do not single-quote it**,
even on PowerShell or bash: Cursor's own command-execution layer can reformat a single-quoted
argument into a double-quoted one before the real shell runs it, which strips the embedded `"`
around the JSON keys and sends `cx` invalid JSON (the `'F' looking for beginning of object key
string` error). Always double-quote the whole value and escape every inner `"` yourself. Use the
form for **your** shell (full explanation in
[`../cx-cli-setup/references/shells.md`](../cx-cli-setup/references/shells.md)):

```bash
# bash / sh — double-quote the whole value, backslash-escape each inner "
"$HOME/.checkmarx/bin/cx" ignore-vulnerability --scan-type asca --data "{\"FileName\":\"example.py\",\"Line\":38,\"RuleID\":4059}"
```

```powershell
# PowerShell — & call operator, double-quote the whole value, double each inner "
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" ignore-vulnerability --scan-type asca --data "{""FileName"":""example.py"",""Line"":38,""RuleID"":4059}"
```

```bat
:: cmd.exe — double-quote the whole value and double each inner "
"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" ignore-vulnerability --scan-type asca --data "{""FileName"":""example.py"",""Line"":38,""RuleID"":4059}"
```

**Preferred when inline JSON still fails — @file syntax** (see
[`../cx-cli-setup/references/shells.md`](../cx-cli-setup/references/shells.md)):

1. `New-Item -ItemType Directory -Force -Path "c:\your\project\.checkmarx" | Out-Null`
2. `Set-Content -Path "c:\your\project\.checkmarx\finding.json" -Value '{"FileName":"example.py","Line":38,"RuleID":4059}' -NoNewline`
3. `& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" ignore-vulnerability --scan-type asca --data "@c:\your\project\.checkmarx\finding.json" --ignored-file-path "c:\your\project\.checkmarx\checkmarxIgnoredTempList.json"`

Use native Windows paths (`c:\…`), not `/c:/…`. After ignore succeeds, **retry the Write/StrReplace once**.

If the command still fails after using the exact form above for your shell, **stop and report it**
— do not retry by re-wrapping it in `bash -c`, `cmd /c`, backtick-escaping, or any other improvised
form; those are more likely to be blocked by the security gate than to fix a quoting problem.

### Constraints

- **All remediation MUST come from `mcp__Checkmarx__codeRemediation`. Never apply a manual, generic, or
  non-MCP fix — if the MCP is unavailable, stop and recover it (Step 2), do not improvise.**
- Do not prompt the user
- Do not skip or reorder fix steps
- Only modify code corresponding to the identified problematic line
- Insert clear `TODO` comments for unresolved issues
- Remediation must be deterministic, auditable, and fully automated

---
