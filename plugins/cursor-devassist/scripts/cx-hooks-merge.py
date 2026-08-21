#!/usr/bin/env python3
"""cx-hooks-merge.py — merge this plugin's rendered hooks into a developer's real hooks.json
without disturbing anything else already in it.

Called by install-hooks.sh, never directly by a hook itself. Two inputs:

  --rendered <path>  the plugin's own hooks JSON with __CURSOR_PLUGIN_ROOT__ already substituted
                      (same shape as hooks/hooks.json.template).
  --target   <path>  the developer's real hooks.json (~/.cursor/hooks.json or a project's
                      .cursor/hooks.json). May not exist yet.

Merge rules, per top-level hook event key present in --rendered (beforeShellExecution,
beforeMCPExecution, preToolUse, stop, and any future ones — the key set is read from --rendered,
never hardcoded, so a new event added to hooks.json.template is picked up automatically):

  1. Any existing entry in --target for that event whose "command" contains one of this plugin's
     own marker substrings (cx_check.sh / cx_run.sh) is dropped — it is a stale copy of OUR hook
     from a previous install, not something the developer added by hand.
  2. Every other existing entry for that event — some other tool's hook — is kept, untouched, in
     its original order.
  3. --rendered's entries for that event are appended after the survivors.

Event keys that exist only in --target (some other tool's hook type entirely) are left alone. The
target's top-level "version" is kept if present; otherwise taken from --rendered. A --target that
exists but fails to parse is left completely untouched (no backup, no write) — this script refuses
to guess at a file the developer can't currently explain either; it exits non-zero with the parse
error so install-hooks.sh can surface it and stop.

If the merge result is identical to what's already on disk (this plugin's required hooks are
already present and current, nothing else changed), the file is left untouched entirely — no
rewrite, no new .bak. That keeps re-running install-hooks.sh (e.g. every `/cx-cli-setup`) a true
no-op when there is nothing to do, instead of clobbering the previous backup and touching the
file's mtime for no reason.
"""

import argparse
import json
import os
import sys

# Distinctive substrings that only ever appear in a command this plugin generated itself —
# matching on these (rather than, say, the plugin root path) survives the plugin being
# reinstalled at a different path and still recognizes its own prior entries.
_OWN_MARKERS = ("cx_check.sh", "cx_run.sh")


def _is_own_entry(entry):
    command = entry.get("command", "") if isinstance(entry, dict) else ""
    return isinstance(command, str) and any(marker in command for marker in _OWN_MARKERS)


def merge(rendered, existing):
    """Return a new dict: existing with this plugin's entries replaced/added per event key
    present in rendered. existing is never mutated in place, so a caller can compare before/after."""
    merged = dict(existing)
    merged.setdefault("version", rendered.get("version", 1))
    merged_hooks = dict(existing.get("hooks", {}))

    for event, rendered_entries in rendered.get("hooks", {}).items():
        if not isinstance(rendered_entries, list):
            continue
        existing_entries = merged_hooks.get(event, [])
        if not isinstance(existing_entries, list):
            existing_entries = []
        survivors = [e for e in existing_entries if not _is_own_entry(e)]
        merged_hooks[event] = survivors + rendered_entries

    merged["hooks"] = merged_hooks
    return merged


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rendered", required=True, help="path to the rendered plugin hooks JSON")
    parser.add_argument("--target", required=True, help="path to the developer's real hooks.json")
    args = parser.parse_args(argv)

    with open(args.rendered, "r", encoding="utf-8") as f:
        rendered = json.load(f)

    target_dir = os.path.dirname(args.target)
    if target_dir:
        os.makedirs(target_dir, exist_ok=True)

    if not os.path.exists(args.target):
        with open(args.target, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rendered, f, indent=2)
            f.write("\n")
        print("Wrote new hooks file: {0}".format(args.target))
        return 0

    with open(args.target, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        existing = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(
            "ERROR: {0} exists but is not valid JSON ({1}). Leaving it untouched — "
            "fix or remove it, then re-run.".format(args.target, exc),
            file=sys.stderr,
        )
        return 1

    if not isinstance(existing, dict):
        print(
            "ERROR: {0} does not contain a JSON object at the top level. Leaving it untouched — "
            "fix or remove it, then re-run.".format(args.target),
            file=sys.stderr,
        )
        return 1

    merged = merge(rendered, existing)
    if merged == existing:
        print("Hooks already up to date: {0} (no changes needed)".format(args.target))
        return 0

    backup_path = args.target + ".bak"
    with open(backup_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(raw)

    with open(args.target, "w", encoding="utf-8", newline="\n") as f:
        json.dump(merged, f, indent=2)
        f.write("\n")

    print("Backed up existing hooks to {0}.bak".format(args.target))
    print("Merged plugin hooks into: {0}".format(args.target))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
