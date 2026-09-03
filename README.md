# Checkmarx Agentic AI
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> Checkmarx application security, built for AI coding agents. This repository holds two ways to bring
> [Checkmarx One](https://checkmarx.com/product/application-security-platform/) into an AI-assisted
> workflow: an **MCP server** your assistant can call, and a **Claude Code plugin** that scans code as it
> is written.

Use them together or separately — they solve different halves of the problem.

## Checkmarx Security MCP


A hosted [MCP](https://modelcontextprotocol.io) server that connects any MCP-capable AI client — Claude,
Cursor, Copilot, Windsurf, Kiro — to Checkmarx One. It exposes scanning, findings, project management,
and AI-generated remediation as tools your assistant can call in conversation.

**Reach for this when** you want your assistant to scan projects, investigate findings, or fix them on
request — in whichever AI client you already use. Configure it once (see
[examples/](examples) for per-client config) and ask.

## How it works (at a glance)

For more details **→ [README-MCP.md](README-MCP.md)**

## cx-devassist plugin

**→ [plugins/cx-devassist/README.md](plugins/cx-devassist/README.md)**

A fail-closed security gate for [Claude Code](https://claude.com/claude-code). Before Claude writes a
file, runs a command, or calls a tool, the Checkmarx `cx` CLI scans the proposed action. Real
vulnerabilities are **blocked rather than silently allowed** — and so is the case where the scanner
itself can't be trusted to run. Findings are remediated through the bundled Checkmarx MCP server.

**Reach for this when** you want the check to be automatic and non-optional rather than something
someone remembers to ask for.

For more details **→ [plugins/cx-devassist/README.md](plugins/cx-devassist/README.md)**

## cx-cursor-plugin

Plugin for [Cursor](https://cursor.com/) that integrates the Checkmarx MCP server directly through the [Cursor's marketplace](https://cursor.com/marketplace) mechanism.

Refer **→ [README-MCP.md](README-MCP.md)** for more details on the MCP server.

For more details **→ [plugins/cx-cursor-plugin/README.md](plugins/cx-cursor-plugin/README.md)**

## cursor-devassist

**→ [plugins/cursor-devassist/README.md](plugins/cursor-devassist/README.md)**

A fail-closed security gate for [Cursor](https://cursor.com/). Before Cursor writes or edits a
scannable file or calls a Checkmarx MCP tool, the Checkmarx `cx` CLI scans the proposed action. Real
vulnerabilities are **blocked rather than silently allowed** — and so is the case where the scanner
itself can't be trusted to run. Findings are remediated through the bundled Checkmarx MCP server.

**Reach for this when** you want the check to be automatic and non-optional rather than something
someone remembers to ask for.

For more details **→ [plugins/cursor-devassist/README.md](plugins/cursor-devassist/README.md)**

## copilot-devassist

**→ [plugins/copilot-devassist/README.md](plugins/copilot-devassist/README.md)**

A fail-closed security gate for [GitHub Copilot CLI](https://github.com/features/copilot/cli). Before
Copilot creates or edits a file, the Checkmarx `cx` CLI scans the proposed content. Real vulnerabilities
are **blocked rather than silently allowed** — and so is the case where the scanner itself can't be
trusted to run. Findings are remediated through the bundled Checkmarx MCP server.

**Reach for this when** you want the check to be automatic and non-optional rather than something
someone remembers to ask for.

For more details **→ [plugins/copilot-devassist/README.md](plugins/copilot-devassist/README.md)**

## codex-devassist

**→ [plugins/codex-devassist/README.md](plugins/codex-devassist/README.md)**

A fail-closed security gate for [OpenAI's Codex CLI](https://developers.openai.com/codex/cli). Before
Codex runs a shell command, applies a patch, or calls a Checkmarx MCP tool, the Checkmarx `cx` CLI
scans the proposed action. Real vulnerabilities are **blocked rather than silently allowed** — and so
is the case where the scanner itself can't be trusted to run. Findings are remediated through the
bundled Checkmarx MCP server.

**Reach for this when** you want the check to be automatic and non-optional rather than something
someone remembers to ask for.

For more details **→ [plugins/codex-devassist/README.md](plugins/codex-devassist/README.md)**


## Documentation

- [docs/usage.md](docs/usage.md) — the MCP tool catalog and example workflows
- [docs/authentication.md](docs/authentication.md) — API key and OAuth2 setup
- [docs/troubleshooting.md](docs/troubleshooting.md) — connection, auth, and scan issues

## License

Apache 2.0 — see [LICENSE](LICENSE) for details. It governs everything in this repository, including the
`cx-devassist` plugin.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines, and [SECURITY.md](SECURITY.md) to report a
vulnerability.

Website: [Checkmarx](https://checkmarx.com/).


© 2026 Checkmarx Ltd.
