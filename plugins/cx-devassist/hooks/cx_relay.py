#!/usr/bin/env python3
"""Strip a permission GRANT out of the native scanner's hook response. Pass everything else through.

WHY THIS EXISTS
    Stage 2 (cx_run.sh) runs `cx hooks claude-pre-file-write` and hands its stdout to Claude Code.
    On a clean scan that stdout carries permissionDecision:"allow", which the host treats as "bypass
    the permission check entirely" — it silently deletes the developer's approval prompt. This gate
    exists to DENY; approving is the developer's call. So exactly one thing is removed here, and
    everything else the scanner says is forwarded untouched.

    The rule is "relay everything EXCEPT an explicit grant", not "relay only a deny". Those differ,
    and the difference is load-bearing — a deny (spaced or compact), an `ask`, a `continue:false`
    and advisory `additionalContext` must all reach the host. CHANGELOG v1.0.2 has the full story,
    including the first attempt at this fix, which got it backwards.

FAIL-SAFE DIRECTION
    Anything unexpected — unparseable stdout, a shape we do not recognise, an internal error — is
    relayed VERBATIM. Never silently swallow scanner output: a dropped deny is a vulnerability
    written to disk, while a forwarded oddity is at worst a visible hook error. The only path that
    produces no output is a payload whose sole content was the grant.
"""

import json
import sys

# The one key in hookSpecificOutput that carries no information — it echoes back the event the host
# already knows. An envelope holding nothing else is worth dropping entirely, so a clean scan emits
# literal silence rather than {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}.
_STRUCTURAL_ONLY_KEYS = {"hookEventName"}


def main(raw):
    if not raw.strip():
        return

    try:
        payload = json.loads(raw)
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        sys.stdout.write(raw)          # unparseable, or not an object — never swallow it
        return

    changed = False

    # Deprecated top-level form. cli.js still maps decision:"approve" -> permissionBehavior "allow".
    if payload.get("decision") == "approve":
        payload.pop("decision")
        payload.pop("reason", None)    # only ever explained the decision now gone
        changed = True

    hook_output = payload.get("hookSpecificOutput")
    if isinstance(hook_output, dict) and hook_output.get("permissionDecision") == "allow":
        hook_output.pop("permissionDecision")
        hook_output.pop("permissionDecisionReason", None)
        changed = True

    # A deny, an ask, continue:false, additionalContext, updatedInput, systemMessage, stopReason —
    # none of these are grants, so none of them are ours to touch.
    if not changed:
        sys.stdout.write(raw)
        return

    if isinstance(hook_output, dict) and set(hook_output) <= _STRUCTURAL_ONLY_KEYS:
        payload.pop("hookSpecificOutput")
    # Nothing of substance survived: say nothing, and the host's normal permission flow decides.
    if payload:
        sys.stdout.write(json.dumps(payload) + "\n")


if __name__ == "__main__":
    # stdin is read ONCE, here, so the fail-safe below still has the payload to fall back on.
    # Reading it inside main() would leave an exhausted stream and turn an internal error into
    # exactly the silent swallow this module exists to prevent.
    _RAW = sys.stdin.read()
    try:
        main(_RAW)
    except Exception:                  # noqa: BLE001 — fail SAFE, never swallow scanner output
        sys.stdout.write(_RAW)
    sys.exit(0)
