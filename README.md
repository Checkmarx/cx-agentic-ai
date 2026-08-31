
<br />
<p align="center">
  <a href="https://github.com/Checkmarx/cx-agentic-ai">
    <img src="logo.png" alt="Logo" width="80" height="80" />
  </a>
  <div align="center">

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![License][license-shield]][license-url]

</div>
  <h3 align="center">Checkmarx Agentic AI</h3>
  <p align="center">Checkmarx application security, built for AI coding agents.</p>
  <p align="center">
    <br />
    <a href="https://github.com/Checkmarx/cx-agentic-ai/issues"><strong>Report Bug</strong></a>
    ·
    <a href="https://github.com/Checkmarx/cx-agentic-ai/issues"><strong>Request Feature</strong></a>
  </p>
</p>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#overview">Overview</a></li>
    <li><a href="#checkmarx-security-mcp">Checkmarx Security MCP</a></li>
    <li><a href="#developer-assist-plugins">Developer Assist Plugins</a></li>
    <li><a href="#checkmarx-one-cli">Checkmarx One CLI</a></li>
    <li><a href="#documentation">Documentation</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#feedback">Feedback</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

## Overview

AI coding assistants generate code quickly, but that code can carry the same security risks as code written by hand. This repository connects [Checkmarx One](https://checkmarx.com/product/application-security-platform/) — Checkmarx's application security platform — to those assistants, so generated code is scanned for vulnerabilities as it's written, not after the fact.

> This repository ships **two** complementary ways to bring Checkmarx One into an AI-assisted workflow. Use them together or separately — they solve different halves of the problem.

- **Checkmarx Security MCP** — a hosted MCP server any MCP-capable assistant can call to scan, inspect findings, and apply AI remediation on demand.
- **Developer Assist plugins** — fail-closed gates that scan scannable file writes *before* they land on disk, for Claude Code, Cursor, and GitHub Copilot CLI.

| Piece | What it does | When to use it |
|---|---|---|
| **Checkmarx Security MCP** | Tools the assistant can *call* — scan a project, inspect findings, apply AI remediation | You want on-demand scanning and fix-it workflows in any MCP client |
| **Developer Assist plugins** | A fail-closed **gate** — scannable file writes are scanned *before* they land on disk | You want the check to be automatic and non-optional |

The plugins wrap the [Checkmarx One CLI (`ast-cli`)](https://github.com/Checkmarx/ast-cli) (`cx`) for install, authentication, and native hook scanning, and they start the same MCP server for remediation.

## Checkmarx Security MCP

A hosted [MCP](https://modelcontextprotocol.io) server that connects any MCP-capable AI client — Claude, Cursor, Copilot, Windsurf, Kiro — to Checkmarx One. It exposes scanning, findings, project management, and AI-generated remediation as tools your assistant can call in conversation.

Configure it once (see [examples/](examples) for per-client config) and ask.

**Details → [README-MCP.md](README-MCP.md)**

### Cursor: MCP-only install

[`plugins/cx-cursor-plugin`](plugins/cx-cursor-plugin) is a lightweight Cursor marketplace plugin that registers the Checkmarx MCP server only — no hook chain, no file-write gate, just the MCP tools. Use it when you want Checkmarx MCP tools in Cursor without adopting the [Developer Assist](#developer-assist-plugins) gate.

**Details → [plugins/cx-cursor-plugin/README.md](plugins/cx-cursor-plugin/README.md)**

## Developer Assist Plugins

Each plugin provides the same fail-closed security gate, wired in as a native hook for its client. Before the agent writes or edits a scannable file, the Checkmarx `cx` CLI scans the proposed content — real vulnerabilities are **blocked rather than silently allowed**, as is the case where the scanner itself can't be trusted to run. Shell commands are never gated. Findings are remediated through the bundled Checkmarx MCP server. Marketplace install and guided `cx` setup follow the same pattern across all three; only the client integration differs.

| Plugin | Client | Details |
|---|---|---|
| `cx-devassist` | [Claude Code](https://claude.com/claude-code) | [plugins/cx-devassist/README.md](plugins/cx-devassist/README.md) |
| `cursor-devassist` | [Cursor](https://cursor.com/) | [plugins/cursor-devassist/README.md](plugins/cursor-devassist/README.md) |
| `copilot-devassist` | [GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli) | [plugins/copilot-devassist/README.md](plugins/copilot-devassist/README.md) |

## Checkmarx One CLI

The plugins install and drive the Checkmarx One CLI (`cx`) from [Checkmarx/ast-cli](https://github.com/Checkmarx/ast-cli). That CLI wraps Checkmarx One APIs for scans, authentication, and the native agent-hook scanners (ASCA, KICS, SCA).

Releases and platform downloads: [ast-cli releases](https://github.com/Checkmarx/ast-cli/releases).

Documentation: [Checkmarx One CLI tool](https://checkmarx.com/resource/documents/en/34965-68620-checkmarx-one-cli-tool.html).

## Documentation

- [README-MCP.md](README-MCP.md) — MCP server overview, auth, and client config
- [docs/usage.md](docs/usage.md) — MCP tool catalog and example workflows
- [docs/authentication.md](docs/authentication.md) — API key and OAuth2 setup
- [docs/troubleshooting.md](docs/troubleshooting.md) — connection, auth, and scan issues
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

## Contributing

We appreciate feedback and contributions. Before you get started, please see:

- [Checkmarx contribution guidelines](CONTRIBUTING.md)
- [Code of Conduct](docs/CODE_OF_CONDUCT.md)

## License

Distributed under the [Apache 2.0](LICENSE) license. It governs everything in this repository, including the MCP server and all plugins.

## Feedback

We'd love to hear your feedback! If you come across a bug or have a feature request, please let us know by submitting an issue in [GitHub Issues](https://github.com/Checkmarx/cx-agentic-ai/issues).

## Contact

Checkmarx One Integrations Team

Project Link: [https://github.com/Checkmarx/cx-agentic-ai](https://github.com/Checkmarx/cx-agentic-ai).

Website: [Checkmarx](https://checkmarx.com/).

© 2026 Checkmarx Ltd. All Rights Reserved.

[contributors-shield]: https://img.shields.io/github/contributors/Checkmarx/cx-agentic-ai.svg
[contributors-url]: https://github.com/Checkmarx/cx-agentic-ai/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/Checkmarx/cx-agentic-ai.svg
[forks-url]: https://github.com/Checkmarx/cx-agentic-ai/network/members
[stars-shield]: https://img.shields.io/github/stars/Checkmarx/cx-agentic-ai.svg
[stars-url]: https://github.com/Checkmarx/cx-agentic-ai/stargazers
[issues-shield]: https://img.shields.io/github/issues/Checkmarx/cx-agentic-ai.svg
[issues-url]: https://github.com/Checkmarx/cx-agentic-ai/issues
[license-shield]: https://img.shields.io/github/license/Checkmarx/cx-agentic-ai.svg
[license-url]: https://github.com/Checkmarx/cx-agentic-ai/blob/main/LICENSE
