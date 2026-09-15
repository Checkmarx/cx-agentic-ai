---
name: cx-devassist-sca
description: "Runs a Checkmarx SCA (OSS) scan on dependency manifests/lockfiles and remediates SCA findings via MCP. Activate when the user explicitly asks to scan or audit dependencies, OR when a hook deny blocked a manifest write with SCA findings (triage first — ask remediate vs suppress before MCP). Do NOT activate for normal manifest create/edit. Invoke as: cx-devassist:cx-devassist-sca"
---

# CX DevAssist SCA

Detects and remediates vulnerable / malicious open-source dependencies using Checkmarx SCA (OSS
realtime). This is the **dependency / package** counterpart to `cx-devassist-asca` (which scans source
code for SAST vulnerabilities).

## When to Use

This skill has two entry points:

1. **On-demand scan** — User **explicitly** asks to scan or audit dependencies for security issues
   (e.g., "scan my dependencies", "audit package.json for vulnerabilities", "are my npm/pip packages
   safe?", "audit go.mod").
2. **Hook triage** — A hook deny blocked a manifest write with SCA findings (activate to present
   findings and ask remediate vs suppress; **do not** auto-call MCP).

**Do NOT activate** when the user is creating, editing, scaffolding, or adding dependencies to a
manifest — e.g. "create package.json", "add validator 13.12.0", "bump lodash". Those writes are
already scanned by the automatic `BeforeTool` hook; activating this skill is redundant and wrong.

> **If SCA findings are already present from an on-demand scan (Flow 1)** — after reporting
> findings, ask whether to remediate before Flow 2.
>
> **If SCA findings are present from a hook deny** — run **Flow 1b: Hook triage** below. **Never**
> skip directly to Flow 2 or call MCP until the developer chooses **remediate**.

### Routing — which Checkmarx capability to use

The plugin exposes three scan surfaces; pick by the target, and ask if it is ambiguous:

| The user wants to scan… | Use |
|---|---|
| A **source code file** (`.py`, `.js`, `.java`, `.go`, …) for code vulnerabilities | `cx-devassist-asca` (SAST) |
| A **dependency manifest / lockfile** (package.json, requirements.txt, go.mod, pom.xml, …) | **this skill** (SCA/OSS) |
| An **entire project / repository** at cloud scale, or existing platform scan results | the Checkmarx MCP (Cx1 cloud) tools |

A bare "scan this file" refers to whatever file is in context: a manifest/lockfile → this skill; source
code → `cx-devassist-asca`. If it is unclear which, ask the user.

## Prerequisites

- Checkmarx `cx` CLI installed. On a first-install session `cx` is in the **canonical store** but not
  yet on the agent shell's PATH, so invoke it by its **absolute path** —
  `"$LOCALAPPDATA/Checkmarx/cx/cx.exe"` on Windows, `"$HOME/.checkmarx/bin/cx"` on Unix (these env vars
  are available in the agent's shell) — and fall back to a bare `cx` only when it is already on PATH.
- Checkmarx MCP server connected (required for remediation).

> **Remediation is MCP-only.** Every fix MUST come from `mcp__Checkmarx__packageRemediation`. If that
> tool is not available, you MUST NOT remediate by any other means — no manual edits to the manifest,
> no generic or LLM-guessed version bumps. Stop and recover the MCP first (see Flow 2 → Step 2).

---

## Flow 1: On-Demand Scan

### Step 1 — Identify the Manifest(s) to Scan

Ask the user which manifest/lockfile to scan if not already specified. Recognized manifests include
`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`,
`go.mod`, `go.sum`, `pom.xml`, `build.gradle`, `build.sbt`.

### Step 2 — Run the SCA (OSS realtime) Scan

Invoke cx by its canonical absolute path (see shell rules below). `-s` accepts a single file or
several files separated by commas. Use a bare `cx` only when it is already on PATH:

```bash
# Unix (macOS/Linux) or Git Bash:
"$HOME/.checkmarx/bin/cx" scan oss-realtime -s "<manifest-path>"
```

```powershell
# Windows (Gemini CLI Shell = PowerShell — & is mandatory):
& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" scan oss-realtime -s "<manifest-path>"
```

### Step 3 — Process Results

The scan returns a JSON response of this shape:

```json
{
  "Packages": [
    {
      "PackageManager": "npm",
      "PackageName": "lodash",
      "PackageVersion": "4.17.15",
      "FilePath": "package.json",
      "Locations": [ { "Line": 12, "StartIndex": 4, "EndIndex": 22 } ],
      "Status": "Vulnerable",
      "Vulnerabilities": [
        { "CVE": "CVE-2020-8203", "Description": "Prototype pollution in lodash", "Severity": "High" }
      ]
    }
  ]
}
```

Interpret each package by its `Status`:
- **`OK`** — clean; no action needed.
- **`Unknown`** — the package could not be resolved against the Checkmarx database. This is **not** a
  guarantee it is safe — tell the user it could not be verified rather than asserting it is clean.
- **`Malicious`** — a known malicious package. Flag it prominently; the safest remediation is removal.
- **Anything else (e.g. `Vulnerable`)** — has known vulnerabilities in `Vulnerabilities[]`.

- **If no package has a `Malicious` or vulnerable `Status`** — inform the user the manifest passed the
  Checkmarx SCA scan with no findings.
- **If there are findings** — report each: `PackageName@PackageVersion` (`PackageManager`), `FilePath`
  and `Locations` line, `Status`, and for each entry in `Vulnerabilities[]` the `CVE`, `Severity`, and
  `Description`. Then ask: **"Would you like me to remediate these findings?"** If yes, go to Flow 2.

---

## Flow 1b: Hook Triage (mandatory after a hook deny)

When a **hook deny** blocked a manifest write and SCA findings are already in context:

1. **Do NOT** re-run the scan, **do NOT** call `mcp__Checkmarx__packageRemediation`, and **do NOT**
   retry the write yet.
2. Present each finding (package, version, CVE, severity, file) from the hook deny message.
3. Ask exactly:

   > A security vulnerability was detected. Would you like to **remediate** it (apply an MCP-driven
   > fix) or **suppress** it (mark as a confirmed false positive and unblock the write)?

4. **Wait** for the developer's answer.
5. **If remediate** → proceed to Flow 2 (all steps — do not stop after MCP or applying the fix).
6. **If suppress** (confirmed false positive only) → run the `cx ignore-vulnerability` command from
   the hook deny message **verbatim** (use the per-shell line for your environment), then retry the
   original write **once**. Do not improvise JSON or paths.
7. If the answer is unclear, ask again — do not default to remediate.
8. **After Flow 2** — when Step 4 shows in-scope findings are resolved, **retry the original blocked
   write once** (file-write tool) so the hook chain confirms the remediated content passes.

---

## Flow 2: Remediation

Triggered **only** after the developer explicitly chooses **remediate** in Flow 1 or Flow 1b, or
explicitly asks you to fix SCA findings.

Once Flow 2 starts, perform **all steps (2 through 5) completely and autonomously** — no further user
prompts. Flow 2 is incomplete if MCP is called or fixes are applied without the Step 4 re-scan.

### Step 1 — Gather Finding Details

For each package to remediate, collect `PackageManager`, `PackageName`, `PackageVersion`, and the
`Vulnerabilities` (CVE list) from the scan.

### Step 2 — Call `mcp__Checkmarx__packageRemediation`

For each finding, call the `mcp__Checkmarx__packageRemediation` tool, passing the affected package's
details. **The tool's own input schema (shown when you invoke it) is the source of truth for the exact
field names** — provide at minimum the package manager, name, version, and the CVE(s):

```json
{
  "packageManager": "[PackageManager from scan]",
  "packageName": "[PackageName from scan]",
  "packageVersion": "[PackageVersion from scan]",
  "vulnerabilities": "[CVE(s) from the finding]",
  "type": "sca"
}
```

If the tool's schema names its fields differently, follow the tool's schema — do not fail the call over
field naming.

- If the tool is **available**: parse `remediation_steps` from the response and proceed to Step 3.
- If the tool is **not available**: **STOP. Do NOT remediate by any other means** — no manual manifest
  edit, no guessed version bump. Leave the dependency **unchanged**. Then recover the MCP:

  1. The extension **declares this MCP in `gemini-extension.json`** (`mcpServers`), so it starts
     automatically when the extension is enabled. If the tool is missing, the usual cause is that
     cx is not configured/authenticated —
     verify with `"$HOME/.checkmarx/bin/cx" auth validate` (Unix) /
     `"$LOCALAPPDATA/Checkmarx/cx/cx.exe" auth validate` (Windows), or a bare `cx auth validate` when
     cx is on PATH; if it fails, run `/cx-cli-setup`.
  2. If auth validation **succeeds**, try calling an MCP tool (e.g. `mcp__Checkmarx__listProjects`)
     — the MCP may already be connected in this session despite any earlier connection warning.
     - If the tool responds → the MCP is live. Proceed with remediation immediately.
     - If the tool is still unavailable → tell the user:

     > "Authentication is valid. Please run `/mcp reload` to reconnect the Checkmarx MCP, then
     > run `/mcp show Checkmarx` to confirm it shows Connected — then ask me to remediate again.
     > I won't apply a non-Checkmarx fix in the meantime."

  Then end the remediation flow without modifying any dependency.

  > Note: do **not** run any `cx_mcp_register.sh` script — this extension registers its MCP via
  > `gemini-extension.json`, and `/mcp reload` is the correct recovery.

### Step 3 — Apply the Fix

- Execute each instruction in `remediation_steps` in order (typically an upgrade to a fixed version, or
  removal for a malicious package).
- Apply manifest/lockfile changes with the **file-write tool** (`WriteFile` / `write_file` / `replace`)
  — not `run_shell_command`. Shell writes bypass hook scanning.
- **Only modify the affected dependency entry** in the manifest/lockfile — do not touch unrelated
  dependencies. For each change, track: file modified, package, old version → new version (or removal).
- Regenerate the lockfile if the ecosystem requires it (e.g. `npm install`, `pip install -r`,
  `go mod tidy`) only when the user's workflow expects it; otherwise note that a lockfile refresh is
  needed.

### Step 4 — Re-scan (mandatory)

Re-run the Flow 1 Step 2 command on the same manifest. **Do not skip this step** — it verifies
remediation worked; it is not optional "proactive scanning".

The scan reads the WHOLE manifest, so it also reports vulnerable packages you never touched.
**Remediate only the findings that belong to the packages you changed in Step 3** — everything else is
pre-existing and out of scope.

Classify every finding against the packages you changed:

- **In scope — remediate.** Either:
  - the package you upgraded/removed is still reported — your fix did not resolve it; or
  - the version you moved to has findings of its own, including a transitive dependency **that version
    pulled in** — your fix introduced it.
- **Out of scope — do NOT fix, and do not touch that dependency.** Any finding for a package you did not
  change, including a transitive dependency that was already in the tree before your change.

Repeat Flow 2 from Step 2 for the in-scope findings **only**. If an in-scope finding survives a second
remediation attempt, stop and report it unresolved — do not keep looping (version ping-pong, where each
upgrade surfaces the next CVE, is the failure mode this bound exists to stop).

Report the out-of-scope findings in the Step 5 summary as pre-existing and unfixed.

### Step 5 — Output Remediation Summary

```
SCA Remediation Summary

Package:   [PackageName] [old-version] → [new-version | REMOVED]
Manager:   [PackageManager]
Issue:     [CVE list] ([highest severity])
File:      [FilePath]

Pre-existing findings (NOT fixed — outside the scope of this remediation):
- [package@version] — [CVE list] — [severity]
- (omit this section entirely when the re-scan reports none)
```

**Final status:**
- ✅ All fixed: "SCA remediation completed. Affected packages upgraded/removed; they are clean on
  re-scan. Any pre-existing findings in packages I did not change are listed above, unfixed."
- ⚠️ Partially fixed: "SCA remediation partially completed — manual review required (e.g. no fixed
  version exists / breaking upgrade). TODOs noted."
- ❌ Failed: "SCA remediation failed. Reason: [summary]. Unresolved packages listed above."

### Suppression (only when the developer chooses suppress in Flow 1b)

When the developer confirms a finding is a **false positive**, use cx's suppression — not a manual edit.
Run the `cx ignore-vulnerability` command from the hook deny message verbatim. Example shape:

```bash
"$HOME/.checkmarx/bin/cx" ignore-vulnerability --scan-type sca --data '<json>'
```

### Constraints

- **All remediation MUST come from `mcp__Checkmarx__packageRemediation`. Never apply a manual, generic,
  or non-MCP fix — if the MCP is unavailable, stop and recover it (Step 2), do not improvise.**
- **Do not skip Step 4** — re-scan is mandatory verification after every remediation
- Do not prompt the user **during** Flow 2 (triage in Flow 1/1b already happened)
- Only modify the dependency entries corresponding to the identified findings.
- Insert clear `TODO` comments where a finding cannot be safely auto-remediated.
- Remediation must be deterministic, auditable, and fully automated.

---
