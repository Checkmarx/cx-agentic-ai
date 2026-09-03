# Upgrade the CLI (below-minimum builds)

Enter here when a hook denied an action because `cx` is **older than the required minimum** (the
deny message names the detected and required versions and includes an `upgrade` command). A
below-minimum build lacks `cx mcp bridge` / `cx auth login`, so the gate hard-blocks every action
— including `cx auth login` — until it is upgraded.

Tell the developer:

> "Your `cx` is older than the version this plugin requires (detected `<X>`, need `<min>`), so
> scanning and the remediation MCP can't run and everything is blocked until it's upgraded.
> Upgrade now? (Y/n)"

On **Y**, run the bootstrap in **upgrade** mode using the resolved absolute path from the deny
message. Do not substitute `${PLUGIN_ROOT}` — it is empty in the shell tool's environment; use the
literal path:

```bash
bash "<plugin-root>/scripts/cx-bootstrap.sh" upgrade
```

It overwrites the resolved `cx` in place (on Windows it renames the running `cx.exe` aside first,
since the live `cx mcp bridge` holds a handle). When it finishes:

- The **scan/auth hooks** re-resolve `cx` on their next run — the next gated tool call is live.
- The **running MCP bridge keeps the old code until the Codex CLI session is restarted** so it
  re-reads `config.toml` and re-spawns the bridge against the upgraded binary (see
  `references/mcp.md`).

**Before doing anything else, reconnect the MCP now — do not skip this even if auth was already
valid before the upgrade.** The upgrade only replaces the binary on disk; the MCP subprocess
Codex CLI already spawned keeps running the OLD binary until it is explicitly re-spawned, and there
is no confirmed hot-reload — a full session restart is required to reconnect. Do this now:

1. Restart the Codex CLI session so it re-reads `config.toml` and re-spawns the bridge.
2. Confirm the Checkmarx MCP server is connected (check your Codex CLI session's MCP connection
   status).

Confirm Checkmarx shows connected before continuing — this is required every time this upgrade path
runs, not just when the full setup flow reaches its own completion step. Skipping it leaves the
remediation MCP silently running the old, below-minimum binary even though `cx version` now reports
the upgraded one.

Then return to **Phase 1a** to confirm the new version, and continue to Phase 2 if needed.
