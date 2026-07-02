# cxone-scanners

A Claude Code plugin marketplace (`cx-secured-agent`) for **Checkmarx CxOne** security scanning.

## Plugins

| Plugin | Description |
|---|---|
| [**cx-security**](./plugins/cx-security) | A fail-closed security gate that scans Claude's file writes, shell commands, and MCP tool calls with the Checkmarx `cx` CLI **before** they happen, and exposes Checkmarx remediation tools over MCP. |

## How it works (at a glance)

Each gated tool call runs a **two-stage PreToolUse chain**:

1. **The gate** (`cx_check`) proves the scanner is trustworthy — cx is present, recent enough,
   capable, and authenticated — or **blocks the action (exit 2)**.
2. **The scanner** (native `cx hooks claude-*`) performs the actual SAST / SCA / policy analysis.

| Tool event | Scans for |
|---|---|
| `Write` / `Edit` | Vulnerabilities in the file content (SAST / ASCA) |
| `Bash` | Risky commands & vulnerable dependencies (SCA) |
| MCP tool calls | Policy violations before the call runs |
| Prompt submit / session stop | Sensitive-content & lifecycle checks |

Only an explicit `exit 2` (deny) blocks — everything else is non-blocking — so the gate is
**fail-closed**: anything it can't prove safe is blocked rather than let through. Remediation runs
through the bundled Checkmarx MCP server (`cx mcp bridge`). Full detail, the plugin structure, and the
fail-closed/cross-OS design are in the **[cx-security README](./plugins/cx-security/README.md)**.

## Install

Register this repository as a local marketplace, then install the plugin:

```bash
claude plugin marketplace add /path/to/cxone-scanners
claude plugin install cx-security@cx-secured-agent
```

Or load it directly for local testing:

```bash
claude --plugin-dir /path/to/cxone-scanners/plugins/cx-security
```

On first use the plugin walks you through installing and authenticating the `cx` CLI via the
`cx-cli-setup` skill. See the [cx-security README](./plugins/cx-security/README.md#prerequisites) for
host prerequisites (Git for Windows, Python 3, a downloader).

## Repository layout

```
cxone-scanners/
├── .claude-plugin/marketplace.json   # marketplace index (cx-secured-agent)
├── plugins/cx-security/              # the plugin (ships to users) — see its README
├── tests/                            # test suite + runner (not shipped with the plugin)
└── .github/workflows/                # tri-OS CI (Ubuntu / macOS / Windows)
```

## License

MIT — see [plugins/cx-security/LICENSE](./plugins/cx-security/LICENSE).
