---
name: cx-test-update
description: "Verifies a Checkmarx DevAssist plugin update landed — reports plugin version and confirms this skill is available. Use when testing marketplace or local plugin updates. Invoke as: /cx-test-update"
disable-model-invocation: true
---

# CX Test Update

**On-demand only** — runs when the developer types `/cx-test-update`. Do not auto-invoke.

## Workflow

1. Resolve `<plugin-root>` (never `${CURSOR_PLUGIN_ROOT}` — empty in the agent shell):
   - Workspace — `plugins/cursor-devassist` (absolute path)
   - Local install — `~/.cursor/plugins/local/cursor-devassist` or cached marketplace path under `~/.cursor/plugins/cache/`

2. Read `<plugin-root>/.cursor-plugin/plugin.json` and extract `version` and `name`.

3. Report success using this template (fill in the values):

   > **Plugin update test passed**
   >
   > - Plugin: `{name}` v`{version}`
   > - Skill: `cx-test-update` loaded from the updated bundle
   > - Path: `{plugin-root}`
   >
   > If you expected a newer version, update the plugin in Cursor (Team Marketplace or local install)
   > and restart the agent session, then run `/cx-test-update` again.

4. If `plugin.json` is missing or unreadable, say which path was tried and stop — do not guess a version.

## Notes

- This skill exists solely to confirm that new plugin content appears after an update.
- No hooks, `cx` CLI, or MCP calls are required for this test.
