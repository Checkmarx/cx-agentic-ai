---
name: cx-devassist-kics
description: "Runs a Checkmarx KICS (IaC) scan on Dockerfile, Terraform, Kubernetes YAML, and similar templates and remediates via MCP. Activate when the user explicitly asks to scan or audit IaC, OR when a hook deny blocked an IaC write with KICS findings (triage first — ask remediate vs suppress before MCP). Do NOT activate for normal IaC create/edit. For source code use cx-devassist-asca; for manifests use cx-devassist-sca. Invoke as: cx-devassist:cx-devassist-kics"
---

# CX DevAssist KICS

Detects and remediates IaC misconfigurations in Dockerfile, Terraform, Kubernetes YAML, and other
Infrastructure-as-Code files using Checkmarx KICS.

## When to Use

This skill has two entry points:

1. **On-demand scan** — User **explicitly** asks to scan an **IaC file** for misconfigurations
   (e.g., "scan this Dockerfile", "check main.tf for issues"). If the target is **source code** use
   `cx-devassist-asca` instead; if it is a **dependency manifest/lockfile** use `cx-devassist-sca`
   instead.
2. **Hook triage** — A hook deny blocked an IaC file write with KICS findings (activate to present
   findings and ask remediate vs suppress; **do not** auto-call MCP).

**Do NOT activate** when the user is creating or editing IaC as part of normal development — those
writes are already scanned by the automatic `BeforeTool` hook.

> **If KICS findings are already present from an on-demand scan (Flow 1)** — after reporting
> findings, ask whether to remediate before Flow 2.
>
> **If KICS findings are present from a hook deny** — run **Flow 1b: Hook triage** below. **Never**
> skip directly to Flow 2 or call MCP until the developer chooses **remediate**.

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
  yet on the agent shell's PATH, so invoke it by its **absolute path** —
  `"$LOCALAPPDATA/Checkmarx/cx/cx.exe"` on Windows, `"$HOME/.checkmarx/bin/cx"` on Unix — and fall back
  to a bare `cx` only when it is already on PATH.
- Checkmarx MCP server connected (required for remediation)
- A running container engine (Docker/Podman) — required by the scan itself, see Error Handling below.

> **Remediation is MCP-only.** Every fix MUST come from `mcp__Checkmarx__codeRemediation` with
> `type: "iac"` — for **all** IaC files, including Dockerfile and docker-compose. Do **not** use
> `imageRemediation` (container image CVE scanning; separate from KICS). If the tool is unavailable,
> stop and recover the MCP — same steps as `cx-devassist-asca` (Flow 2 → Step 2).

---

## Flow 1: On-Demand Scan

### Step 1 — Identify Files to Scan

Ask the user which file(s) to scan if not already specified.

### Step 2 — Run the KICS (IaC realtime) Scan

**Gemini CLI on Windows uses PowerShell for `run_shell_command` / Shell** — use the `&` call operator.
On Unix/macOS use bash-style invocation. Use a bare `cx` only when it is already on PATH:

```bash
# Unix (macOS/Linux) or Git Bash:
"$HOME/.checkmarx/bin/cx" scan iac-realtime -s "<file-path>"
```

```powershell
# Windows (Gemini CLI Shell = PowerShell — & is mandatory):
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan iac-realtime -s "<file-path>"
```

### Error Handling — Container Engine Not Available

`cx scan iac-realtime` depends on a running container engine (Docker/Podman). If neither is
available or running, the command exits non-zero with a clear, actionable stderr message
identifying the problem (for example, *"container engine 'docker' is installed but not running"*).

On **hook writes**, when the guardrail cannot scan, the edit may still be allowed but with a
visible skip note — relay that note to the user; do not treat it as a clean scan. See
`skills/cx-cli-setup/references/troubleshooting.md` → KICS / IaC scans.

- Relay stderr or skip-note messages to the user verbatim — do not paraphrase or invent troubleshooting.
- Do not silently retry, fall back to a partial scan, or proceed to remediation using stale findings.
- Do not report the file as "clean" when the scan could not run.
- Once the user resolves it (start Docker/Podman, or set `CX_HOOKS_CONTAINER_ENGINE`), re-run the
  exact same scan command unchanged.

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
- `Locations[0].Line` — location of the offending configuration (0-based in scan JSON)
- `Description` — what the misconfiguration is

- **If there are no findings** — Inform the user the file passed the KICS IaC scan with no findings.
- **If there are findings** — Report each finding, then ask:
  **"Would you like me to remediate these findings?"** If yes, proceed to Flow 2 below.

---

## Flow 1b: Hook Triage (mandatory after a hook deny)

When a **hook deny** blocked a write and KICS findings are already in context:

1. **Do NOT** re-run the scan, **do NOT** call `mcp__Checkmarx__codeRemediation`, and **do NOT** retry
   the write yet.
2. Present each finding (title, severity, file, line, description) from the hook deny message.
3. Ask exactly:

   > A security vulnerability was detected. Would you like to **remediate** it (apply an MCP-driven
   > code fix) or **suppress** it (mark as a confirmed false positive and unblock the write)?

4. **Wait** for the developer's answer.
5. **If remediate** → proceed to Flow 2 (all steps — do not stop after MCP or applying the fix).
6. **If suppress** (confirmed false positive only) → run the `cx ignore-vulnerability` command from
   the hook deny message **verbatim** (use the per-shell line for your environment), then retry the
   original write **once**. Do not improvise JSON or paths.
7. If the answer is unclear, ask again — do not default to remediate.
8. **After Flow 2** — when Step 4 re-scan shows in-scope findings are resolved, **retry the original
   blocked write once** (file-write tool) so the hook chain confirms the remediated content passes.

---

## Flow 2: Remediation

Triggered **only** after the developer explicitly chooses **remediate** in Flow 1 or Flow 1b, or
explicitly asks you to fix KICS findings.

Once Flow 2 starts, perform **all steps (1 through 5) completely and autonomously** — no further user
prompts. Flow 2 is incomplete if MCP is called or fixes are applied without the Step 4 re-scan.

### Step 1 — Call `mcp__Checkmarx__codeRemediation`

For each finding, call `mcp__Checkmarx__codeRemediation` with `type: "iac"`:

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

- If the tool is **available**: parse `remediation_steps` and proceed to Step 3.
- If the tool is **not available**: **STOP.** Do not remediate manually. Follow MCP recovery in
  `cx-devassist-asca` (Flow 2 → Step 2), then end without modifying code.

### Step 3 — Apply the Fix

- Execute each instruction in `remediation_steps` in order.
- Apply changes with the **file-write tool** (`WriteFile` / `write_file` / `replace`) — not
  `run_shell_command`. Shell writes bypass hook scanning.
- **Only modify code at or near the flagged line** — do not touch unrelated code.
- For each change, track file, line number, and before → after values.

### Step 4 — Re-scan (mandatory)

After all fixes are applied, re-run (same shell rules as Flow 1 Step 2). **Do not skip this step:**

```bash
"$HOME/.checkmarx/bin/cx" scan iac-realtime -s "<file-path>"
```

```powershell
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan iac-realtime -s "<file-path>"
```

Classify every finding against the changes you tracked in Step 3. Remediate in-scope findings only;
report out-of-scope findings in the Step 5 summary as pre-existing and unfixed.

Repeat Flow 2 from Step 1 for in-scope findings **only**. Stop after a second failed attempt on the
same finding.

### Step 5 — Output Remediation Summary

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

### Suppression (only when explicitly requested and justified)

If the user decides to accept/ignore a specific IaC finding rather than fix it, run
`cx ignore-vulnerability --scan-type iac` with JSON containing `Title` and `SimilarityID` from the
finding (or use the exact command from the hook deny message). Run one command per finding. After
ignore succeeds, retry the blocked write once.

### Constraints

- **All remediation MUST come from `mcp__Checkmarx__codeRemediation` (`type: "iac"`). Never use
  `imageRemediation` or manual fixes — if the MCP is unavailable, stop and recover it (Step 1).**
- **Do not skip Step 4** — re-scan is mandatory verification after every remediation
- Do not prompt the user **during** Flow 2 (triage in Flow 1/1b already happened)
- Suppress only on explicit user request with stated justification
