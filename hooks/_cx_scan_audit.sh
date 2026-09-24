# _cx_scan_audit.sh — derive allowlisted scan_decision fields from native cx hook stdout.
# Sourced by cx_run.sh after stage-2 scanner output is captured. Best-effort only; never raises.
#
# When KICS fail-opens (container engine down / missing), ast-cli surfaces a user_message like:
#   "Checkmarx IaC guardrail skipped Dockerfile: container engine 'docker' is installed but not running..."
# When both Docker and Podman are installed but neither daemon is running, ast-cli emits:
#   "... container engines 'docker' and 'podman' are installed but not running..."
# We map those to redacted enums for cx_log.py — never log the message text itself.

# Sets _CXSCAN_REASON_CODE (optional override) and _CXSCAN_LOG_EXTRAS (guardrail, engine, skip_reason).
cx_scan_audit_extras() {
    _CXSCAN_REASON_CODE=
    _CXSCAN_LOG_EXTRAS=
    case "$1" in
        *IaC\ guardrail\ skipped*)
            _CXSCAN_REASON_CODE=iac_scan_skipped
            _CXSCAN_LOG_EXTRAS="guardrail=kics"
            case "$1" in
                *docker*\ and\ *podman*\ are\ installed\ but\ not\ running*)
                    _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS skip_reason=all_engines_not_running container_engine=both"
                    ;;
                *installed\ but\ not\ running*)
                    _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS skip_reason=engine_not_running"
                    case "$1" in
                        *container\ engine\ \'docker\'* | *container\ engine\ 'docker'*) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=docker" ;;
                        *container\ engine\ \'podman\'* | *container\ engine\ 'podman'*) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=podman" ;;
                        *) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=unknown" ;;
                    esac
                    ;;
                *container\ engine\ *not\ found*) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS skip_reason=engine_not_found" ;;
                *Failed\ to\ pull\ KICS\ image*) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS skip_reason=image_pull_failed" ;;
                *)
                    _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS skip_reason=scan_error"
                    case "$1" in
                        *container\ engine\ \'docker\'* | *container\ engine\ 'docker'*) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=docker" ;;
                        *container\ engine\ \'podman\'* | *container\ engine\ 'podman'*) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=podman" ;;
                        *) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=unknown" ;;
                    esac
                    ;;
            esac
            # engine_not_found / image_pull_failed: name whichever engine appears in the note
            case "$_CXSCAN_LOG_EXTRAS" in
                *container_engine=*) : ;;
                *)
                    case "$1" in
                        *container\ engine\ \'docker\'* | *container\ engine\ 'docker'*) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=docker" ;;
                        *container\ engine\ \'podman\'* | *container\ engine\ 'podman'*) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=podman" ;;
                        *) _CXSCAN_LOG_EXTRAS="$_CXSCAN_LOG_EXTRAS container_engine=unknown" ;;
                    esac
                    ;;
            esac
            ;;
    esac
}
