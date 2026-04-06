---
name: cx-cli-setup
description: Installs the Checkmarx cx CLI if it is not found on the system. Use when the cx CLI is missing. Invoke as: cx-security:cx-cli-setup
---

# CX CLI Setup

Installs the Checkmarx `cx` CLI so that security scanning features work correctly.

## When to Use

- The `cx` CLI is not installed or not found in PATH
- A hook has blocked an operation because `cx` is missing
- The user explicitly asks how to install the Checkmarx CLI

---

## Steps

### Step 1 — Inform the User

Tell the user that the Checkmarx `cx` CLI is required for security scanning and was not found. Let them know you will install it now via Homebrew.

### Step 2 — Install

Run the following command:

```bash
brew install checkmarx/ast-cli/ast-cli
```

The user will be prompted to approve the command execution.

### Step 3 — Verify

After installation completes, verify by running:

```bash
cx version
```

- If it returns a version number — confirm success: "cx CLI is installed and ready."
- If it fails — let the user know they may need to open a new terminal window for PATH to refresh, then retry verification.

### Step 4 — Resume

Inform the user that their original operation will now be retried automatically (the hook will re-run and pass this time).

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-06 | Initial release |
