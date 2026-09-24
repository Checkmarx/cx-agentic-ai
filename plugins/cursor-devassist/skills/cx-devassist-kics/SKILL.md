---
name: cx-devassist-kics
description: "Runs a Checkmarx KICS (Keeping Infrastructure as Code Secure) scan on an IaC file — Dockerfile, Terraform, Kubernetes YAML, and similar templates — to detect infrastructure misconfigurations, and remediates findings using the Checkmarx MCP tool. Use when a user asks to scan or fix an IaC file (Dockerfile, *.tf, *.yaml/*.yml, *.json IaC templates, *.auto.tfvars, *.terraform.tfvars, *.proto) for misconfigurations. For source code use cx-devassist-asca instead; for dependency manifests/lockfiles use cx-devassist-sca instead. Invoke as: /cx-devassist-kics"
---

# CX DevAssist KICS

Detects and remediates IaC misconfigurations in Dockerfile, Terraform, Kubernetes YAML, and other
Infrastructure-as-Code files using Checkmarx KICS.

## When to Use

This skill has two entry points:

1. **On-demand scan** — User asks to scan an **IaC file** for misconfigurations (e.g., "scan this
   Dockerfile", "check main.tf for issues"). If the target is **source code** use `cx-devassist-asca`
   instead; if it is a **dependency manifest/lockfile** use `cx-devassist-sca` instead.
2. **Remediation** — User asks to fix KICS findings, the agent receives a **hook deny** on Write/StrReplace (`agent_message` / `CHECKMARX_HOOK_DENY`), or KICS findings are surfaced via the stop hook's `followup_message`.

> **If KICS findings are already present in context** (hook deny `agent_message`, `CHECKMARX_HOOK_DENY` block, prior scan result, or stop-hook message), **skip Flow 1 entirely** and proceed directly to Flow 2. Do not retry the blocked write, paste code in chat, or use shell workarounds.

### Routing — which Checkmarx capability to use

Pick by the target, and ask if it is ambiguous:

| The user wants to scan… | Use |
|---|---|
| A **source code file** (`.py`, `.js`, `.java`, `.go`, `.ts`, …) for code vulnerabilities | `cx-devassist-asca` (SAST) |
| A **dependency manifest / lockfile** (package.json, requirements.txt, go.mod, pom.xml, …) | `cx-devassist-sca` (SCA/OSS) |
| An **IaC file** (`Dockerfile`, `*.tf`, `*.yaml`/`*.yml`, `*.json` IaC templates, `*.auto.tfvars`, `*.terraform.tfvars`, `*.proto`) for infrastructure misconfigurations | **this skill** (IaC/KICS) |
| An **entire project / repository** at cloud scale, or existing platform scan results | the Checkmarx MCP (Cx1 cloud) tools |

A bare "scan this file" refers to whatever file is in context: an IaC file → this skill; source code →
`cx-devassist-asca`; a manifest/lockfile → `cx-devassist-sca`. If it is unclear which, ask the user.

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
- A running container engine (Docker/Podman) — required by the scan itself, see Error Handling below.

> **Remediation is MCP-only.** Every fix MUST come from `mcp__plugin-cx-devassist-Checkmarx__codeRemediation`
> with `type: "iac"` — for **all** IaC files, including Dockerfile and docker-compose. Do **not** use
> `imageRemediation` (container image CVE scanning; separate from KICS). If the tool is unavailable,
> stop and recover the MCP — same steps as `cx-devassist-asca` (Flow 2 → Step 2).

---

## Flow 1: On-Demand Scan

### Step 1 — Identify Files to Scan

Ask the user which file(s) to scan if not already specified.

### Step 2 — Run the KICS (IaC realtime) Scan

Invoke cx by its canonical absolute path so it resolves even when cx isn't on the agent shell's PATH
(a first-install session); use a bare `cx` only when cx is already on PATH.

```bash
# bash / sh (macOS, Linux):
"$HOME/.checkmarx/bin/cx" scan iac-realtime -s "<file-path>"
# bash / sh (Git Bash on Windows):
"$LOCALAPPDATA/Checkmarx/cx/cx.exe" scan iac-realtime -s "<file-path>"
```

```powershell
# PowerShell (Cursor's default shell on Windows) - the & call operator is REQUIRED
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan iac-realtime -s "<file-path>"
```

```bat
:: cmd.exe
"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" scan iac-realtime -s "<file-path>"
```

### Error Handling — Container Engine Not Available

`cx scan iac-realtime` depends on a running container engine (Docker/Podman). If neither is
available or running, the command exits non-zero with a clear, actionable stderr message
identifying the problem (for example, *"container engine 'docker' is installed but not running"*).

On **hook writes**, when the guardrail cannot scan, the edit may still be allowed but with a
visible skip note in the hook response — relay that note to the user; do not treat it as a clean scan.

- Relay stderr or skip-note messages to the user verbatim — do not paraphrase, summarize into a
  generic "scan failed", or invent your own troubleshooting steps.
- Do not silently retry, fall back to a partial scan, or proceed to remediation using
  stale/assumed findings.
- Do not report the file as "clean" when the scan could not run — that's indistinguishable
  from a real clean result and strictly worse than saying nothing.
- Once the user resolves it (start Docker/Podman, or set `CX_HOOKS_CONTAINER_ENGINE` — see
  [`../cx-cli-setup/references/troubleshooting.md`](../cx-cli-setup/references/troubleshooting.md)),
  re-run the exact same scan command unchanged.

### Step 3 — Process Results

The scan returns a JSON array of findings. Each entry has this shape:

```json
{
  "Title": "Missing User Instruction",
  "SimilarityID": "7540e8c3cdc3b13c3a24b8ce501d9e39fb485368e20922df18cec9564e075049",
  "Severity": "High",
  "Description": "A user should be specified in the dockerfile",
  "FilePath": "Dockerfile",
  "Platform": "Dockerfile",
  "Locations": [{ "Line": 3 }]
}
```

Report each finding:
- `Title` — the misconfiguration rule that matched
- `SimilarityID` — stable identifier (required for suppression)
- `Severity` — Critical / High / Medium / Low
- `Locations[0].Line` (or `line` when flattened) — location of the offending configuration
- `Description` — what the misconfiguration is

- **If there are no findings** — Inform the user the file passed the KICS IaC scan with no findings.
- **If there are findings** — Report each finding as above, then ask the user:
  **"Would you like me to remediate these findings?"** If yes, proceed to the Remediation flow below.

---

## Flow 2: Remediation

Triggered either after the user confirms in Flow 1, or when IaC misconfigurations detected by KICS need to be fixed.

Perform all steps **completely and autonomously** — no user interaction.

### Step 1 — Call `mcp__plugin-cx-devassist-Checkmarx__codeRemediation`

For each finding, call `mcp__plugin-cx-devassist-Checkmarx__codeRemediation` (same tool as ASCA; use
`type: "iac"` instead of `sast`):

```json
{
  "type": "iac",
  "metadata": {
    "title": "[Title from finding]",
    "description": "[Description from finding]",
    "remediationAdvice": "[how to harden this configuration]"
  }
}
```

- If the tool is **available**: parse `remediation_steps` and proceed to Step 2.
- If the tool is **not available**: **STOP.** Do not remediate manually. Follow MCP recovery in
  `cx-devassist-asca` (Flow 2 → Step 2), then end without modifying code.

### Step 2 — Apply the Fix

- Execute each instruction in `remediation_steps` in order.
- **Only modify code at or near the flagged line** (`line` from scan results) — do not touch unrelated code.
- For each change, track:
  - File modified
  - Line number
  - Description of the change
  - Before → after values

If a fix genuinely requires resources outside this file (e.g. a separate KMS key or a
centrally-managed policy), add them as part of your change rather than skipping the finding.

### Step 3 — Re-scan

After all fixes are applied, re-run (same canonical absolute-path invocation as Flow 1 Step 2;
bare `cx` only when it is on PATH):

```bash
# bash / sh (macOS, Linux):
"$HOME/.checkmarx/bin/cx" scan iac-realtime -s "<file-path>"
# bash / sh (Git Bash on Windows):
"$LOCALAPPDATA/Checkmarx/cx/cx.exe" scan iac-realtime -s "<file-path>"
```

```powershell
# PowerShell (Cursor's default shell on Windows) - the & call operator is REQUIRED
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan iac-realtime -s "<file-path>"
```

```bat
:: cmd.exe
"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" scan iac-realtime -s "<file-path>"
```

The scan reads the WHOLE file, so it also reports findings you never touched. **Remediate only
the findings that belong to your own changes (or the original target)** — everything else is
pre-existing and out of scope.

Classify every finding against the changes you tracked in Step 2:

- **In scope — remediate.** Either:
  - the finding you set out to fix is still there (same `title`, at or near its original line) — your
    fix did not resolve it; or
  - the finding sits on a line you added or modified — your fix introduced it.
- **Out of scope — do NOT fix, and do not edit that code.** Every other finding: it lives in code you
  did not touch and was already there before you started.

Repeat Flow 2 from Step 1 for the in-scope findings **only**. If an in-scope finding survives a second
remediation attempt, stop and report it unresolved — do not keep looping.

Report the out-of-scope findings in the Step 4 summary as pre-existing and unfixed; leave their code
alone.

### Step 4 — Output Remediation Summary

`Locations[0].Line` from scan is 0-based — show **`Line + 1`** in this summary (1-based, matches editors).

```
IaC Remediation Summary

Rule:             [title]
Severity:         [severity]
Issue Type:       IaC Misconfiguration
Problematic Line: [Line + 1]

Files Modified:
1. [file]
   - Line [n]: [description of change]

Pre-existing findings (NOT fixed — outside the scope of this remediation):
- [title] — line [Line + 1] — [severity]
- (omit this section entirely when the re-scan reports none)
```

**Final status:**
- ✅ All fixed: "Remediation completed for [title]. IaC file is clean on re-scan."
- ⚠️ Partially fixed: "Remediation partially completed — manual review required. TODOs inserted where applicable."
- ❌ Failed: "Remediation failed for [title]. Reason: [summary]. Unresolved issues listed above."

### Suppression (only when explicitly requested and justified)

If the user decides to accept/ignore a specific IaC finding rather than fix it (e.g. after a hook
deny on Write/StrReplace, per `rules/cx-hook-deny.mdc`'s "Other deny types" table), use cx's
suppression rather than a manual edit or a shell workaround. The finding shape for KICS is:

```json
{"Title": "<Title from scan>", "SimilarityID": "<SimilarityID from scan>"}
```

When the hook deny embeds ready-made commands in `agent_message`, run those exactly. Otherwise
build the JSON from the scan output fields above.

The `--data` value is a JSON document, so it is full of double quotes. **On PowerShell, use `--%`
stop-parsing** (preferred — see
[`../cx-cli-setup/references/shells.md`](../cx-cli-setup/references/shells.md)) — but `--%` only
stops PowerShell from reparsing the remainder; it still reaches `cx.exe`'s own Windows argv parser,
which only keeps an embedded `"` when it's backslash-escaped inside one outer quoted region. Wrap
the whole JSON value in one outer `"..."` and backslash-escape the inner `"` even under `--%`. On
cmd/bash, double-quote the whole value and escape every inner `"` yourself. **Do not single-quote it**
on any shell: Cursor's own command-execution layer can reformat a single-quoted argument into a
double-quoted one before the real shell runs it, which strips the embedded `"` around the JSON keys
and sends `cx` invalid JSON.

**Suppressing more than one finding? Run one `ignore-vulnerability` command per finding, each as
its own separate Shell tool call — never join two with `;`, `&&`, or `||` on one line.** This is
especially important with `--%`: it makes PowerShell stop parsing for the *rest of that entire
line*, so a `;` placed after it is not a statement separator anymore.

```powershell
# PowerShell — preferred: --%, JSON wrapped in one outer quote, inner quotes backslash-escaped
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" --% ignore-vulnerability --scan-type iac --data "{\"Title\":\"Missing User Instruction\",\"SimilarityID\":\"7540e8c3cdc3b13c3a24b8ce501d9e39fb485368e20922df18cec9564e075049\"}"
```

```bash
# bash / sh — double-quote the whole value, backslash-escape each inner "
"$HOME/.checkmarx/bin/cx" ignore-vulnerability --scan-type iac --data "{\"Title\":\"Missing User Instruction\",\"SimilarityID\":\"7540e8c3cdc3b13c3a24b8ce501d9e39fb485368e20922df18cec9564e075049\"}"
```

```bat
:: cmd.exe — double-quote the whole value and double each inner "
"%LOCALAPPDATA%\Checkmarx\cx\cx.exe" ignore-vulnerability --scan-type iac --data "{""Title"":""Missing User Instruction"",""SimilarityID"":""7540e8c3cdc3b13c3a24b8ce501d9e39fb485368e20922df18cec9564e075049""}"
```

**Preferred when inline JSON still fails — @file syntax** (see
[`../cx-cli-setup/references/shells.md`](../cx-cli-setup/references/shells.md)):

1. `New-Item -ItemType Directory -Force -Path "c:\your\project\.checkmarx" | Out-Null`
2. `Set-Content -Path "c:\your\project\.checkmarx\finding.json" -Value '{"Title":"Missing User Instruction","SimilarityID":"7540e8c3..."}' -NoNewline`
3. `& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" ignore-vulnerability --scan-type iac --data "@c:\your\project\.checkmarx\finding.json" --ignored-file-path "c:\your\project\.checkmarx\checkmarxIgnoredTempList.json"`

Use native Windows paths (`c:\…`), not `/c:/…`. After ignore succeeds, **retry the Write/StrReplace once**.

If the command still fails after using the exact form above for your shell, **stop and report it**
— do not retry by re-wrapping it in `bash -c`, `cmd /c`, backtick-escaping, or any other improvised
form; those are more likely to be blocked by the security gate than to fix a quoting problem.

### Constraints

- **All remediation MUST come from `mcp__plugin-cx-devassist-Checkmarx__codeRemediation`
  (`type: "iac"`). Never use `imageRemediation` or manual fixes — if the MCP is unavailable, stop
  and recover it (Step 1).**
- Do not prompt the user during Flow 2, except to ask about suppression when the user explicitly
  requests it.
- Findings are fixed by default — suppress only on explicit user request with a stated justification
  (accepted risk, compensating control, or a finding that doesn't apply to this deployment context).
- Only modify code corresponding to the identified problematic line.
- Insert clear `TODO` comments for unresolved issues.
- Remediation must be deterministic, auditable, and fully automated.

---
