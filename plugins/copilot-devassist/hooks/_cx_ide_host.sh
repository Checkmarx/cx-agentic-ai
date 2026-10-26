# _cx_ide_host.sh — VS Code host detection and the VS Code "Checkmarx Self-Healing" switch, for the
# shell stages (cx_run.sh, and cx_check.sh's no-Python branch). POSIX sh; sourced, never executed.
#
# The SAME rules as cx_check.py (_in_vscode / _load_ide_config / _ide_self_healing_disabled),
# kept cheap enough to run on every hook: one case match, and the IDE file is only parsed when it exists.
#
# Host rule (same as cx_check.py's _in_vscode). First match wins:
#   1. PLUGIN_ROOT (set by the host to the plugin folder it runs; verified by the AST-186850 PoC):
#      .../agentPlugins/... → VS Code (VS Code always runs its own copy there, whether the plugin was
#      installed by the Copilot CLI or from VS Code's marketplace); .../.copilot/installed-plugins/... →
#      the terminal Copilot CLI (also when started in VS Code's integrated terminal).
#   2. Only when PLUGIN_ROOT says neither: GITHUB_COPILOT_INTEGRATION_ID=vscode-chat (set by VS Code on
#      the Copilot CLI engine it bundles), then VS Code-shaped stdin (tool_name / tool_input /
#      hook_event_name / session_id). The terminal sends camelCase toolName / toolArgs, and its toolArgs
#      is a JSON STRING (any key inside is escaped as \"key\"), so a raw `"tool_name"` cannot come from it.
# Never keyed off TERM_PROGRAM / VSCODE_*: the integrated terminal inherits those.

# 0 when this hook runs inside VS Code ("$1" is the raw hook stdin), else 1.
cx_in_vscode() {
    _cxide_root=$(printf '%s' "${PLUGIN_ROOT:-}" | tr '\\' '/' | tr '[:upper:]' '[:lower:]')
    # Terminal marker first: VS Code's folder names encode the source path with dashes, so they never
    # contain it, while a terminal path could contain "agentPlugins" by chance.
    case "$_cxide_root" in
        */.copilot/installed-plugins/*) return 1 ;;
        */agentplugins/*)               return 0 ;;
    esac
    [ "${GITHUB_COPILOT_INTEGRATION_ID:-}" = vscode-chat ] && return 0
    case "$1" in
        *'"tool_name"'* | *'"tool_input"'* | *'"hook_event_name"'* | *'"session_id"'*) return 0 ;;
    esac
    return 1
}

# 0 ONLY when ~/.checkmarx/cx-onboarding-ide.properties is VALID (exists, readable, <= 8 KB,
# cx_schema_version absent or 1) AND cx_self_healing_enabled is false/0/no/off/disabled (trimmed,
# case-insensitive). Anything else — missing file, unknown schema, missing key, any other value — is
# ON (returns 1). `key=value` lines, `#` comment lines, UTF-8 BOM and CRLF tolerated, last one wins.
# Home mirrors Python's os.path.expanduser("~"): USERPROFILE on Windows, HOME elsewhere.
cx_ide_self_healing_off() {
    case "$(uname -s 2>/dev/null)" in
        MINGW* | MSYS* | CYGWIN*) _cxide_home="${USERPROFILE:-${HOME:-}}" ;;
        *)                        _cxide_home="${HOME:-}" ;;
    esac
    [ -n "$_cxide_home" ] || return 1
    _cxide_file="$_cxide_home/.checkmarx/cx-onboarding-ide.properties"
    [ -f "$_cxide_file" ] && [ -r "$_cxide_file" ] || return 1
    _cxide_size=$(wc -c < "$_cxide_file" 2>/dev/null | tr -d ' ') || return 1
    [ -n "$_cxide_size" ] && [ "$_cxide_size" -le 8192 ] 2>/dev/null || return 1
    _cxide_state=$(LC_ALL=C awk -v bom="$(printf '\357\273\277')" '
        NR == 1 && index($0, bom) == 1 { $0 = substr($0, length(bom) + 1) }
        {
            sub(/\r$/, "")
            line = $0
            gsub(/^[ \t]+|[ \t]+$/, "", line)
            if (line == "" || substr(line, 1, 1) == "#") next
            i = index(line, "=")
            if (i == 0) next
            k = substr(line, 1, i - 1); v = substr(line, i + 1)
            gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v)
            if (k == "cx_schema_version") { schema = v; has_schema = 1 }
            if (k == "cx_self_healing_enabled") heal = tolower(v)
        }
        END {
            if (has_schema && schema != "1") print "on"
            else if (heal ~ /^(false|0|no|off|disabled)$/) print "off"
            else print "on"
        }' "$_cxide_file" 2>/dev/null)
    [ "$_cxide_state" = off ]
}
