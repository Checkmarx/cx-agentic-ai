---
name: codex-devassist-asca
description: "Runs a Checkmarx ASCA (AI Security Code Assistant) SAST scan on a SOURCE CODE file to detect code vulnerabilities, and remediates findings using the Checkmarx MCP tool. Use when a user asks to scan or fix a source code file (.py/.js/.java/.go/.ts/…) for security vulnerabilities. For dependency manifests/lockfiles (package.json, requirements.txt, go.mod, …) use codex-devassist-sca instead. Invoke as: $codex-devassist-asca"
---

# CX Security ASCA

Detects and remediates SAST vulnerabilities in source files using Checkmarx ASCA.

## When to Use

This skill has two entry points:

1. **On-demand scan** — User asks to scan a **source code file** for vulnerabilities (e.g., "scan this
   file", "check app.py for security issues"). If the target is a **dependency manifest/lockfile**
   (package.json, requirements.txt, go.mod, …), use `codex-devassist-sca` instead.
2. **Remediation** — User asks to fix ASCA findings, or Codex needs to fix SAST vulnerabilities detected by ASCA

> **If ASCA findings are already present in context** (e.g., provided by a hook block or a prior scan result), **skip Flow 1 entirely** and proceed directly to Flow 2 using those findings. Do not re-run the scan.

### Routing — which Checkmarx capability to use

Pick by the target, and ask if it is ambiguous:

| The user wants to scan… | Use |
|---|---|
| A **source code file** (`.py`, `.js`, `.java`, `.go`, `.ts`, …) for code vulnerabilities | **this skill** (SAST/ASCA) |
| A **dependency manifest / lockfile** (package.json, requirements.txt, go.mod, pom.xml, …) | `codex-devassist-sca` (SCA/OSS) |
| An **entire project / repository** at cloud scale, or existing platform scan results | the Checkmarx MCP (Cx1 cloud) tools |

A bare "scan this file" refers to whatever file is in context: source code → this skill; a
manifest/lockfile → `codex-devassist-sca`. If it is unclear which, ask the user.

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

Run the scan on each file. Invoke cx by its canonical absolute path so it resolves even when cx isn't
on the agent shell's PATH (a first-install session); use a bare `cx` only when cx is already on PATH:

```bash
# Unix (macOS/Linux):
"$HOME/.checkmarx/bin/cx" scan asca -s "<file-path>"
# Windows (Git Bash):
"$LOCALAPPDATA/Checkmarx/cx/cx.exe" scan asca -s "<file-path>"
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

  1. The plugin ships a best-effort `.mcp.json`, but Codex CLI's supported registration path is a
     manual `[mcp_servers.Checkmarx]` stanza in `~/.codex/config.toml` or `<repo>/.codex/config.toml`
     (see `references/mcp.md`). If the tool is missing, first confirm cx itself is configured/
     authenticated — the bridge can't derive the URL or auth header without a valid key. Verify with
     cx by its canonical absolute path — `"$HOME/.checkmarx/bin/cx" auth validate` (Unix) or
     `"$LOCALAPPDATA/Checkmarx/cx/cx.exe" auth validate` (Windows), or a bare `cx auth validate` when
     cx is on PATH; if it fails (or reports no API key), run `$codex-cli-setup`.
  2. Then tell the user the **one** step only they can perform — Codex CLI loads MCP servers at
     startup, so the server can't become live in this running session on its own:

     > "The Checkmarx remediation MCP isn't connected in this session. Please confirm the
     > `[mcp_servers.Checkmarx]` entry exists in your `~/.codex/config.toml` (or `.codex/config.toml`)
     > — see `$codex-cli-setup` → `references/mcp.md` for the exact snippet — then restart the Codex
     > CLI session so it re-reads config.toml and reconnects the server — then ask me to remediate
     > again. I won't apply a non-Checkmarx fix in the meantime."

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
# Unix (macOS/Linux):
"$HOME/.checkmarx/bin/cx" scan asca -s "<file-path>"
# Windows (Git Bash):
"$LOCALAPPDATA/Checkmarx/cx/cx.exe" scan asca -s "<file-path>"
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
- Do not prompt the user
- Do not skip or reorder fix steps
- Only modify code corresponding to the identified problematic line
- Insert clear `TODO` comments for unresolved issues
- Remediation must be deterministic, auditable, and fully automated

---
