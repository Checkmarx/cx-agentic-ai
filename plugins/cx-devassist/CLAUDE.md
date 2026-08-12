# Checkmarx cx-devassist (Claude Code)

This plugin provides **automatic security hooks** and **on-demand skills**. They serve different
purposes — do not conflate them.

## Automatic hooks (always on)

`PreToolUse` hooks run on every `Write`, `Edit`, `MultiEdit`, and `Bash` tool call without skill
activation:

- **Gate** (`cx_check`) — proves `cx` is installed, capable, and authenticated.
- **Scanner** (`cx hooks claude-pre-file-write` / `claude-pre-tool-use`) — scans proposed file content
  (SAST for source, SCA for manifests like `package.json`).

When the user asks you to **create, edit, scaffold, or add dependencies to any file** — including
`package.json`, `requirements.txt`, or `go.mod` — **do not activate any Checkmarx skill**. Just
perform the write. The hook chain scans the proposed content automatically and will deny the tool call
if a real finding or policy violation is detected.

If a write is **denied by a hook** because a security finding was detected:

1. **STOP** — do not retry the write, do not call Checkmarx MCP tools, and do not apply fixes yet.
2. **Present the findings** from the hook deny message (file, rule, severity, description).
3. **Ask the developer** (mandatory):

   > A security vulnerability was detected. Would you like to **remediate** it (apply an MCP-driven
   > code fix) or **suppress** it (mark as a confirmed false positive and unblock the write)?

4. **Wait for the answer** before doing anything else.
5. **If remediate** — activate the relevant skill and run its **Flow 2** only:
   - Source code (SAST/ASCA) → `cx-devassist-asca`
   - Dependency manifest (SCA/OSS) → `cx-devassist-sca`
6. **If suppress** (confirmed false positive only) — run the `cx ignore-vulnerability` command from
   the hook deny message **verbatim** (per-shell form), then retry the original write **once**.
7. **Never auto-remediate** on a hook deny. Calling `mcp__Checkmarx__codeRemediation` or
   `mcp__Checkmarx__packageRemediation` without the developer choosing **remediate** is wrong.

For hook denies about missing/outdated/unauthenticated `cx`, activate `cx-cli-setup` (`/cx-cli-setup`)
instead.

## On-demand skills (explicit only)

Activate a bundled skill when the user **explicitly** requests a security scan, audit, or remediation
— or after hook triage when the developer chooses **remediate**.

| User intent | Skill |
|---|---|
| Scan/audit **source code** for vulnerabilities | `cx-devassist-asca` |
| Scan/audit **dependencies / manifests** for vulnerabilities | `cx-devassist-sca` |
| Install, upgrade, or authenticate `cx` | `cx-cli-setup` |

**Do NOT activate skills for:**

- Creating or editing `package.json`, lockfiles, or other manifests
- Adding or bumping a dependency version
- Normal feature work, scaffolding, refactors, or test runs
- Proactive scanning the user did not ask for
