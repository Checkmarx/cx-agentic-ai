# CxOne ASCA Security Plugin

A Claude Code plugin that runs **Checkmarx ASCA** (Application Security Code Analysis) scans automatically before every `Write` or `Edit` tool call.

When a vulnerability is detected, Claude is instructed to fix it silently and retry — no user interruption required.

## Prerequisites

- [Checkmarx CxOne CLI (`cx`)](https://checkmarx.com/resource/documents/en/34965-68621-checkmarx-one-cli-tool.html) installed and on your `$PATH`
- `cx` authenticated to your CxOne tenant

## Installation

### Option 1 — Local marketplace (recommended for on-prem / team use)

Register this repo as a local marketplace, then install the plugin at project scope:

```bash
claude plugin marketplace add /path/to/cxone-scanners --scope project
claude plugin install cxone-asca-security@cxone-scanners --scope project
```

Verify:

```bash
claude plugin list
# cxone-asca-security@cxone-scanners  v1.0.0  project  ✔ enabled
```

### Option 2 — Direct plugin-dir (quick local testing)

```bash
claude --plugin-dir /path/to/cxone-scanners/plugins/cxone-asca-security
```

### Option 3 — From a remote marketplace (once published)

```
/plugin install cxone-asca-security
```

### Reload after updating hook scripts

```
/reload-plugins
```

## How it works

| Event | Hook | Behaviour |
|---|---|---|
| `Write` (new file) | `asca-scan-write.py` | Scans the full file content before writing |
| `Edit` (patch file) | `asca-scan-edit.py` | Applies the diff in a temp file and scans only **new** vulnerabilities introduced by the change |

If findings are detected the hook returns `permissionDecision: deny` with a structured reason listing every vulnerability and its `remediationAdvise`. Claude then fixes each issue and retries automatically (up to 5 attempts).

## Project-level CLAUDE.md rules

Add the following to your project's `CLAUDE.md` so Claude knows how to handle scan denials:

```markdown
## ASCA Security — Autonomous Remediation

When a `Write` or `Edit` is blocked by the ASCA hook (`permissionDecision: deny`,
reason starts with "ASCA security scan detected vulnerabilities"):

1. **Never ask the user.** Fix silently and retry immediately.
2. **Apply every fix** listed in the denial reason using the provided `remediationAdvise`.
   Fix Critical/High before Medium/Low.
3. **Retry** until the scan passes. After 5 failed attempts, report remaining findings to the user.
4. **After success**, emit one line summarizing what was fixed and why.

Do not add `# TODO` comments, use `# nosec` suppressions, or change anything beyond
what the vulnerability requires.
```

## Plugin structure

```
cxone-scanners/
├── .claude-plugin/
│   ├── plugin.json              # Root manifest (for --plugin-dir installs)
│   └── marketplace.json         # Marketplace index
├── plugins/
│   └── cxone-asca-security/
│       ├── .claude-plugin/
│       │   └── plugin.json      # Plugin manifest
│       └── hooks/
│           ├── hooks.json       # PreToolUse wiring (auto-loaded)
│           ├── asca-scan-write.py
│           └── asca-scan-edit.py
├── hooks/                       # Top-level copies (for --plugin-dir use)
├── .claude/                     # Local dev settings (not distributed)
│   ├── hooks/
│   └── settings.json
├── CLAUDE.md                    # Autonomous-remediation rules for Claude
└── README.md
```

## License

MIT
