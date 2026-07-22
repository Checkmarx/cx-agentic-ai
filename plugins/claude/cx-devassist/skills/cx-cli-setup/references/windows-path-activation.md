# Windows PATH & the cx binary (activation is automatic)

**You normally do not need anything on this page.** The security gate resolves `cx` from the
**canonical store** (`%LOCALAPPDATA%\Checkmarx\cx\cx.exe`) by **absolute path**, so running
`scripts/cx-bootstrap.sh install` unblocks the gate on your **next tool call with no restart** — even
though a running Claude Code froze its PATH at startup and cannot see a newly-persisted PATH entry.

**Do not hand-place a `cx.exe` into a PATH folder, and do not download the binary yourself.** The
bootstrap already installs to the canonical store, verifies the checksum (fail-closed by default), and
adds the store to your **User PATH** for future sessions. Hand-placing a second copy creates drift and
is exactly the workaround the gate is designed to make unnecessary.

**Key fact (why the gate does not rely on PATH):** a running process's PATH is frozen at launch;
`setx` / registry edits only affect *future* processes. That is precisely why the gate resolves an
absolute path instead of waiting for a PATH refresh.

**The remediation MCP** resolves cx by absolute path too (it launches via `hooks/cx_run.sh`, same
precedence as the gate) and starts at session start, so it activates after **one `/reload-plugins`** —
no restart, and no need to hand-edit `.mcp.json` or put cx on PATH for it.

**Locked-down machine, or an internal capable build living elsewhere:** point the gate at an explicit
binary with the **`CX_BINARY`** override — see `references/troubleshooting.md`. The stage-2 scanner
(`hooks/cx_run.sh`) honors it too, so scanning runs the same binary the gate validated.
