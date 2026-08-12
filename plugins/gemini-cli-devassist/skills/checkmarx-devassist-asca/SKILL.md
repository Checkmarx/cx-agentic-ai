---
name: checkmarx-devassist-asca
description: "Runs a Checkmarx ASCA SAST scan on SOURCE CODE files and remediates SAST findings via MCP. Activate when the user explicitly asks to scan or audit a source file, OR when a hook deny blocked a source-file write with SAST findings (triage first — ask remediate vs suppress before MCP). Do NOT activate for normal code creation or edits. For dependency manifests use checkmarx-devassist-sca. Invoke as: cx-devassist:checkmarx-devassist-asca"
---

# CX Security ASCA

Detects and remediates SAST vulnerabilities in source files using Checkmarx ASCA.

## When to Use

This skill has two entry points:

1. **On-demand scan** — User **explicitly** asks to scan a **source code file** for security
   vulnerabilities (e.g., "scan app.py for security issues", "audit this file for SAST findings"). If
   the target is a **dependency manifest/lockfile** (package.json, requirements.txt, go.mod, …), use
   `checkmarx-devassist-sca` instead.
2. **Hook triage** — A hook deny blocked a source-file write with SAST findings (activate to present
   findings and ask remediate vs suppress; **do not** auto-call MCP).

**Do NOT activate** when the user is writing or editing source code as part of normal development —
those writes are already scanned by the automatic `BeforeTool` hook.

> **If ASCA findings are already present from an on-demand scan (Flow 1)** — after reporting
> findings, ask whether to remediate before Flow 2.
>
> **If ASCA findings are present from a hook deny** — run **Flow 1b: Hook triage** below. **Never**
> skip directly to Flow 2 or call MCP until the developer chooses **remediate**.

### Routing — which Checkmarx capability to use

Pick by the target, and ask if it is ambiguous:

| The user wants to scan… | Use |
|---|---|
| A **source code file** (`.py`, `.js`, `.java`, `.go`, `.ts`, …) for code vulnerabilities | **this skill** (SAST/ASCA) |
| A **dependency manifest / lockfile** (package.json, requirements.txt, go.mod, pom.xml, …) | `checkmarx-devassist-sca` (SCA/OSS) |
| An **entire project / repository** at cloud scale, or existing platform scan results | the Checkmarx MCP (Cx1 cloud) tools |

A bare "scan this file" refers to whatever file is in context: source code → this skill; a
manifest/lockfile → `checkmarx-devassist-sca`. If it is unclear which, ask the user.

## Prerequisites

- Checkmarx `cx` CLI installed. On a first-install session `cx` is in the **canonical store** but not
  yet on the agent shell's PATH, so invoke it by its **absolute path** —
  `"$LOCALAPPDATA/Checkmarx/cx/cx.exe"` on Windows, `"$HOME/.checkmarx/bin/cx"` on Unix (these env vars
  are available in the agent's shell) — and fall back to a bare `cx` only when it is already on PATH.
- Checkmarx MCP server connected (required for remediation)

> **Remediation is MCP-only.** Every fix MUST come from `mcp__Checkmarx__codeRemediation`. If that tool
> is not available, you MUST NOT remediate by any other means — no manual edits, no generic or
> LLM-generated fixes, and do not apply the `remediationAdvise` text yourself. Stop and recover the MCP
> first (see Flow 2 → Step 2, "If the tool is not available").

---

## Flow 1: On-Demand Scan

### Step 1 — Identify Files to Scan

Ask the user which file(s) to scan if not already specified.

### Step 2 — Run the ASCA Scan

Run the scan on each file. **Gemini CLI on Windows uses PowerShell for `run_shell_command` / Shell** —
a quoted path alone is NOT a command; you must use the `&` call operator. On Unix/macOS use bash-style
invocation. Use a bare `cx` only when it is already on PATH:

```bash
# Unix (macOS/Linux) or Git Bash:
"$HOME/.checkmarx/bin/cx" scan asca -s "<file-path>"
```

```powershell
# Windows (Gemini CLI Shell = PowerShell — & is mandatory):
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan asca -s "<file-path>"
```

**Do NOT** run `"$LOCALAPPDATA/Checkmarx/cx/cx.exe" scan asca ...` on Windows — PowerShell treats the
quoted path as a string expression and then fails on `scan` (`Unexpected token 'scan'`).

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
  If yes, proceed to Flow 2 below.

---

## Flow 1b: Hook Triage (mandatory after a hook deny)

When a **hook deny** blocked a write and SAST findings are already in context:

1. **Do NOT** re-run the scan, **do NOT** call `mcp__Checkmarx__codeRemediation`, and **do NOT** retry
   the write yet.
2. Present each finding (rule, severity, file, line, description) from the hook deny message.
3. Ask exactly:

   > A security vulnerability was detected. Would you like to **remediate** it (apply an MCP-driven
   > code fix) or **suppress** it (mark as a confirmed false positive and unblock the write)?

4. **Wait** for the developer's answer.
5. **If remediate** → proceed to Flow 2.
6. **If suppress** (confirmed false positive only) → run the `cx ignore-vulnerability` command from
   the hook deny message **verbatim** (use the per-shell line for your environment), then retry the
   original write **once**. Do not improvise JSON or paths.
7. If the answer is unclear, ask again — do not default to remediate.

---

## Flow 2: Remediation

Triggered **only** after the developer explicitly chooses **remediate** in Flow 1 or Flow 1b, or
explicitly asks you to fix ASCA findings.

Once Flow 2 starts, perform all steps **completely and autonomously** — no further user prompts.

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

  1. The plugin **declares this MCP in `.mcp.json`**, so it starts automatically when the plugin is
     enabled. If the tool is missing, the usual cause is that cx is not configured/authenticated —
     the bridge can't derive the URL or auth header without a valid key. Verify with cx by its
     canonical absolute path — `"$HOME/.checkmarx/bin/cx" auth validate` (Unix) or
     `"$LOCALAPPDATA/Checkmarx/cx/cx.exe" auth validate` (Windows), or a bare `cx auth validate` when
     cx is on PATH; if it fails (or reports no API key), run `/checkmarx-cli-setup`.
  2. If auth validation **succeeds**, try calling an MCP tool (e.g. `mcp__Checkmarx__listProjects`)
     — the MCP may already be connected in this session despite any earlier connection warning.
     - If the tool responds → the MCP is live. Proceed with remediation immediately.
     - If the tool is still unavailable → tell the user:

     > "Authentication is valid. Please run `/restart` to reconnect the Checkmarx MCP, then
     > run `/mcp show Checkmarx` to confirm it shows Connected — then ask me to remediate again.
     > I won't apply a non-Checkmarx fix in the meantime."

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

After all fixes are applied, re-run (same shell rules as Flow 1 Step 2; bare `cx` only when on PATH):

```bash
# Unix (macOS/Linux) or Git Bash:
"$HOME/.checkmarx/bin/cx" scan asca -s "<file-path>"
```

```powershell
# Windows (Gemini CLI Shell = PowerShell):
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan asca -s "<file-path>"
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

### Constraints

- **All remediation MUST come from `mcp__Checkmarx__codeRemediation`. Never apply a manual, generic, or
  non-MCP fix — if the MCP is unavailable, stop and recover it (Step 2), do not improvise.**
- Do not prompt the user **during** Flow 2 (triage in Flow 1/1b already happened)
- Do not skip or reorder fix steps
- Only modify code corresponding to the identified problematic line
- Insert clear `TODO` comments for unresolved issues
- Remediation must be deterministic, auditable, and fully automated

---
