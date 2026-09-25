# Checkmarx cx-devassist (Gemini CLI)

This extension provides **automatic security hooks** and **on-demand skills**. They serve different
purposes — do not conflate them.

## Automatic hooks (always on)

`BeforeTool` hooks run on **scannable file writes** (`WriteFile`, `write_file`, `write_.*`, `replace`)
and **Checkmarx MCP calls** (`mcp_.*`) without skill activation:

- **Gate** (`cx_check`) — proves `cx` is installed, capable, and authenticated before a scannable
  write or MCP call proceeds.
- **Scanner** (`cx hooks gemini-before-file-tool` / `gemini-before-tool`) — scans proposed file
  content (ASCA/SAST, KICS/IaC, SCA/manifests) or enforces MCP policy.

**Shell commands (`run_shell_command`) are not gated.** A single non-blocking observer records OAuth
URL/tenant pairs from `cx auth login` so a later session can offer them — it never blocks.

An **`AfterAgent` lifecycle hook** (`cx hooks gemini-after-agent`) runs at the end of each agent turn for
advisory cleanup/telemetry — the Gemini equivalent of Claude Code's `Stop` → `claude-stop`. It is
non-blocking and does not gate writes or MCP calls.

Writes to file types Checkmarx **cannot** scan (`.md`, `.css`, `.sql`, `.sh`, plain `.txt`, etc.)
proceed without the readiness gate. See `config/cx-scannable-files` and
`docs/gemini-cli-devassist.md` for the full list.

When the user asks you to **create, edit, scaffold, or add dependencies** as part of normal
development — and is **not** explicitly asking for a security scan or audit:

- **Do not** proactively activate `cx-devassist-asca`, `cx-devassist-sca`, or `cx-devassist-kics`.
  Use the file-write tool directly instead.
- **Scannable files** (`package.json`, `requirements.txt`, `app.py`, `main.tf`, … — see
  `config/cx-scannable-files`) are checked by the automatic hook chain: readiness gate first, then
  native scan of the proposed content. The write is denied if `cx` is not ready or a real finding is
  detected.
- **Unscannable files** (`.md`, `.css`, `.sql`, `.sh`, plain `.txt`, …) are not gated — proceed
  with the write normally.
- If a hook denies because **`cx` is missing, outdated, or unauthenticated**, activate
  `cx-cli-setup`, fix readiness, then **retry the same write** — do not skip setup and do not
  activate ASCA/SCA skills instead.
- If a hook denies because of a **security finding**, follow the triage flow below (remediate vs
  suppress) — do not retry the write until the developer decides.

If a write is **denied by a hook** because a security finding was detected:

1. **STOP** — do not retry the write yet.
2. **Present the findings** from the hook deny message (file, rule, severity, description).
3. **Remediate by default** — activate the relevant skill and run **Flow 2 in full (Steps 2–5)**;
   this never needs the developer's permission first (same model as Claude Code / Codex / Copilot /
   Cursor):
   - Source code (SAST/ASCA) → `cx-devassist-asca`
   - Dependency manifest (SCA/OSS) → `cx-devassist-sca`
   - IaC file (KICS) → `cx-devassist-kics`
   - **Step 4 re-scan is mandatory** — run `cx scan asca`, `cx scan oss-realtime`, or
     `cx scan iac-realtime` on the same file/manifest after fixes. This is verification, not
     "proactive scanning".
   - Apply fixes with the **file-write tool** (`WriteFile` / `write_file` / `replace`) — not
     `run_shell_command`. Shell writes are not scanned by hooks.
4. **Suppressing instead of remediating is a legitimate autonomous decision** — not every finding
   needs a developer checkpoint — but only when grounded in something you can verify **in the file
   itself**. Each skill's "Suppression" section states its exact confidence bar (e.g. provably
   unreachable/dead code, a visible sanitizer/guard, or — for SCA — an actual remediation attempt
   that came back with no fixed version). An intentionally-inserted vulnerability/misconfiguration is
   never a free pass for suppression, no matter how confident you are it's deliberate — ask the
   developer instead.
5. **Not confident either way** — ask the developer rather than guessing:

   > A security vulnerability was detected. Would you like to **remediate** it (apply an MCP-driven
   > code fix) or **suppress** it (mark as a confirmed false positive and unblock the write)?

6. **After Flow 2, or after a confident/developer-approved suppression** — retry the original
   blocked write once (same file-write tool) so the hook chain confirms the fix/suppression took
   effect.
7. **If suppressing**, run the `cx ignore-vulnerability` command from the hook deny message
   **verbatim** (per-shell form), then retry the write.
8. **Tell the developer what you did and why**, even when it didn't need asking first — autonomous
   is not the same as silent.

For hook denies about missing/outdated/unauthenticated `cx`, activate `cx-cli-setup` instead.

## On-demand skills (explicit only)

Activate a bundled skill **only** when the user **explicitly** requests a security scan, audit, or
remediation — or when a hook deny needs Flow 2 (remediation is the default there; run the relevant
skill's Flow 2 in full, including Step 4 re-scan).

| User intent | Skill |
|---|---|
| Scan/audit **source code** for vulnerabilities | `cx-devassist-asca` |
| Scan/audit **dependencies / manifests** for vulnerabilities | `cx-devassist-sca` |
| Scan/audit **IaC** (Dockerfile, Terraform, K8s YAML, …) for misconfigurations | `cx-devassist-kics` |
| Install, upgrade, or authenticate `cx` | `cx-cli-setup` |

**Do NOT activate skills for:**

- Creating or editing `package.json`, lockfiles, or other manifests
- Adding or bumping a dependency version (e.g. `"validator": "13.12.0"`)
- Normal feature work, scaffolding, refactors, or test runs
- Proactive "let me scan first" behavior the user did not ask for

**Exception:** hook deny → activate ASCA, SCA, or KICS and complete Flow 2 (Steps 2–5) — remediation
runs by default there, suppression only when that skill's confidence bar is met or the developer
says so. Step 4 re-scan is required verification, not proactive scanning.

Hooks still scan scannable writes automatically (`config/cx-scannable-files`); this list only means
do not proactively invoke the on-demand ASCA/SCA/KICS scan skills. `cx-cli-setup` remains appropriate
when hooks report `cx` is not ready.

Mentioning a filename like `package.json` or a package name like `validator` in a **create/edit**
request is **not** a scan request.
