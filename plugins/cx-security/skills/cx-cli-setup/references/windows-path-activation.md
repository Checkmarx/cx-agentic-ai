# Windows install & in-session PATH activation

**Key fact (why this matters):** a running Claude Code captured its PATH at startup and hands
that frozen copy to every hook and the MCP server. A *new* folder added to PATH (`setx`,
`$env:PATH +=`, registry edits) is **not** visible to this session — only to future processes.
But the **files** inside the already-on-PATH folders are live. So the trick is to **place
`cx.exe` into a folder that is already on PATH**, not to change PATH.

Tell the developer:

> "I'll download the Checkmarx One CLI and place `cx.exe` in a folder that's already on your
> PATH, so it works in this session without a restart."

On confirmation:

```powershell
# 1. Download + extract to a canonical store
$store = "$env:LOCALAPPDATA\Checkmarx\cx"
New-Item -ItemType Directory -Force -Path $store | Out-Null
Invoke-WebRequest -Uri "https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_windows_x64.zip" -OutFile "$env:TEMP\cx-cli.zip"
Expand-Archive "$env:TEMP\cx-cli.zip" -DestinationPath $store -Force

# 2. ACTIVATE for THIS session: copy cx.exe into the FIRST writable folder already on PATH.
#    (Skip WindowsApps — it rejects loosely-dropped .exe files. Use a create+delete probe,
#     not the read-only bit, because Windows ACLs make a permission bit unreliable.)
$target = $env:PATH -split ';' |
  Where-Object { $_ -and (Test-Path $_) -and ($_ -notlike '*\WindowsApps') } |
  Where-Object {
    try { $p = Join-Path $_ ('.cxw_' + [guid]::NewGuid()); New-Item $p -ItemType File -Force -EA Stop | Out-Null; Remove-Item $p -Force; $true } catch { $false }
  } | Select-Object -First 1
if ($target) {
  Copy-Item "$store\cx.exe" (Join-Path $target 'cx.exe') -Force
  Write-Host "cx.exe activated in: $target  (usable in this session)"
} else {
  Write-Host "NO writable folder on PATH was found — see the fallback note below."
}

# 3. Make it permanent for FUTURE sessions (does NOT affect the current session).
#    Read AND write the *User* PATH only, via the .NET API. Do NOT use
#    `setx PATH "$env:PATH;$store"`: that writes the merged System+User+session PATH back into
#    User scope, TRUNCATES it at 1024 chars (silently corrupting PATH), and folds System
#    entries permanently into the User PATH.
$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if (-not $userPath) { $userPath = '' }
if (($userPath -split ';' | Where-Object { $_ }) -notcontains $store) {
  $newPath = ($userPath.TrimEnd(';') + ';' + $store).Trim(';')
  [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
}
```

- **If step 2 found a folder:** `cx` is usable now. The scan/auth hooks pick it up on their next
  run (they re-resolve `cx` on every fire). For the MCP, run `/reload-plugins` (see
  `references/mcp.md`) — no full restart.
- **If step 2 found NO writable PATH folder** (locked-down machine): either (a) point the gate at
  the absolute `cx.exe` path with the `CX_BINARY` override (see `references/troubleshooting.md`)
  and set `.mcp.json`'s `command` to that path, then `/reload-plugins`; or (b) restart Claude Code
  — the User-PATH update in step 3 already made it permanent, so the new session finds it.
