---
name: cx-install-wiring
description: "On-demand first-time Checkmarx DevAssist setup (intended for Cursor CLI): wires hooks and rules, then continues into cx CLI install and auth. When the developer types /cx-install-wiring, always run the workflow — do not refuse based on IDE vs CLI detection. Invoke as: /cx-install-wiring"
disable-model-invocation: true
---

# CX Install Wiring (on demand — intended for Cursor CLI)

**On-demand only** — runs when the developer explicitly types `/cx-install-wiring`. Do **not** auto-invoke
this skill from hook denies or missing `cx`.

### If `/cx-install-wiring` was invoked — always run Phase 1

There is **no reliable environment signal** to tell Cursor CLI from the IDE Agent panel. When the
developer typed `/cx-install-wiring`, **proceed immediately with Phase 1** (scope → `install-hooks.sh`).

**Forbidden:**

- Refusing with "this skill runs only from Cursor CLI" or telling them to open a terminal / run
  `agent` / type `/cx-install-wiring` again — unless they **explicitly say** they are in the IDE chat
  panel and cannot use the Shell tool.
- Guessing that the session is IDE based on workspace paths, Windows paths, or chat UI alone.

**Documentation note (not a gate):** This flow is **designed for Cursor CLI** (terminal `agent`). IDE
users who need hooks should run `install-hooks.sh` manually (see README) or use `/cx-cli-setup` for
`cx` only — but do **not** block a slash-command invocation on that assumption.

**Never** tell the developer to use **Developer: Reload Window**, the Command Palette, or IDE MCP
settings — those apply to the IDE, not Cursor CLI.

Then wire hooks and rules and **automatically** continue into `cx` install/auth via
`skills/cx-cli-setup/SKILL.md` — do not ask the developer to run `/cx-cli-setup` separately.

**Do not** run `Get-Command cx`, `cx auth validate`, or any other `cx` command in this phase.

### Scope

**Question 1 — ask once:**

> "Install Checkmarx hooks and rules for: **(1) User** — all projects (`~/.cursor/`), or **(2) Project**
> — one specific repo (`<repo>/.cursor/`)?"

- **User** → run `install-hooks.sh` with no extra env vars (see below).
- **Project** → ask **Question 2** before running the installer. Do **not** assume "this repo" without
  the developer's choice.

**Question 2 — only when they chose Project:**

> "Which repo should get project-scoped hooks and rules?
> **(A) This repo** — the directory you're in now (`<show resolved absolute path>`)
> **(B) Another path** — reply with the absolute path to that repo's root."

Resolve **"this repo"** as the first path that exists (in order):

1. `$CURSOR_PROJECT_DIR` from the session, if set
2. The workspace / project root Cursor CLI opened in
3. `pwd` from a single `pwd` Shell command (allowed for path resolution only — not a `cx` command)

If they chose **(B)**, use the path they provide (normalize to an absolute path). **Validate** the
directory exists before `install-hooks.sh` (`../cx-cli-setup/references/shells.md` → "Check a directory
exists"). If it does not exist, say so and ask again — do not run the installer at a typo'd path.

Pass the validated path as `CX_PROJECT_PATH` (see below).

### Run the installer

Resolve `<plugin-root>` (never `${CURSOR_PLUGIN_ROOT}` — empty in the agent shell):

1. Workspace — `plugins/cursor-devassist` (absolute path)
2. Local install — `~/.cursor/plugins/local/cursor-devassist` or `cx-devassist-cursor`

```bash
# User scope
bash "<plugin-root>/scripts/install-hooks.sh"

# Project scope
CX_CURSOR_HOOKS_TARGET=project CX_PROJECT_PATH="<validated-path>" bash "<plugin-root>/scripts/install-hooks.sh"
```

Report the script output (hooks merged/written; rules installed/updated/already up to date).

## Phase 2 — Continue into cx CLI setup (automatic — no user prompt)

Immediately after Phase 1 succeeds — **without asking** the developer to continue:

1. **Read** `skills/cx-cli-setup/SKILL.md` (same plugin: `../cx-cli-setup/SKILL.md` from this skill).
2. **Follow that file from Phase 0 through Phase 4** in this same session. Use its `references/`
   for shell syntax, OAuth, and troubleshooting.
3. Where `cx-cli-setup` Phase 4 says **Developer: Reload Window** or IDE MCP settings, **skip that**
   for this CLI flow — the completion message below replaces it.
4. Do **not** re-run `install-hooks.sh` or repeat Phase 1.

This is not a separate slash command — you load and execute the other skill's instructions directly.

## Complete (CLI — say this at the end)

Only after Phase 2 finishes. Use wording like:

> "Setup complete. Hooks, rules, and the `cx` CLI are configured.
>
> **Restart your terminal session** so Cursor CLI picks up the new hooks and rules:
> - Exit the agent (`/exit` or Ctrl+C), then run `agent` again in this directory, **or**
> - Close and reopen the terminal, then `cd` back to the project and run `agent`.
>
> After restart, the security gate and MCP bridge should be active. If a tool call is still blocked,
> run `/cx-cli-setup` to recover."

Do **not** mention Developer: Reload Window, Command Palette, or the IDE MCP panel.
