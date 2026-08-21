#!/usr/bin/env python3
"""cx-rules-install.py — sync this plugin's Cursor rules into user or project .cursor/rules/

Called by install-hooks.sh, never directly by a hook. Two inputs:

  --source <path>  the plugin's rules/ directory (plain .mdc files, no templating).
  --target <path>  ~/.cursor/rules or <repo>/.cursor/rules. Created if missing.

Install rules:

  1. Every .mdc file in --source is copied into --target.
  2. Files owned by this plugin use the cx-*.mdc prefix. Only those are replaced on re-run;
     every other rule in --target is left untouched.
  3. Stale cx-*.mdc files present in --target but no longer shipped in --source are removed
     (after backing up to <name>.mdc.bak) so upgrades do not leave orphaned rules behind.
  4. When a target file already exists and differs, it is backed up to <name>.mdc.bak before
     overwrite. Identical files are skipped (no backup, no mtime churn).

If --target exists but is not a directory, the script exits non-zero and makes no changes.
"""

import argparse
import filecmp
import os
import shutil
import sys

_OWN_PREFIX = "cx-"


def _list_plugin_rules(source_dir):
    names = []
    for name in os.listdir(source_dir):
        if name.endswith(".mdc") and os.path.isfile(os.path.join(source_dir, name)):
            names.append(name)
    return sorted(names)


def install_rules(source_dir, target_dir):
    """Return (changed, messages) where changed is True if anything was written or removed."""
    messages = []
    changed = False

    source_names = set(_list_plugin_rules(source_dir))
    if not source_names:
        messages.append("WARNING: no .mdc rules found in {0}".format(source_dir))
        return False, messages

    os.makedirs(target_dir, exist_ok=True)

    installed = []
    updated = []
    skipped = []
    backed_up = []

    for name in sorted(source_names):
        src = os.path.join(source_dir, name)
        dst = os.path.join(target_dir, name)
        if os.path.exists(dst):
            if filecmp.cmp(src, dst, shallow=False):
                skipped.append(name)
                continue
            shutil.copy2(dst, dst + ".bak")
            backed_up.append(name)
            updated.append(name)
        else:
            installed.append(name)
        shutil.copy2(src, dst)
        changed = True

    removed = []
    for name in sorted(os.listdir(target_dir)):
        if not name.endswith(".mdc") or not name.startswith(_OWN_PREFIX):
            continue
        if name in source_names:
            continue
        path = os.path.join(target_dir, name)
        if not os.path.isfile(path):
            continue
        shutil.copy2(path, path + ".bak")
        os.remove(path)
        removed.append(name)
        changed = True

    if not changed:
        messages.append("Rules already up to date: {0}".format(target_dir))
        return False, messages

    for name in backed_up:
        messages.append("Backed up existing rule to {0}.bak".format(os.path.join(target_dir, name)))
    for name in installed:
        messages.append("Installed rule: {0}".format(os.path.join(target_dir, name)))
    for name in updated:
        messages.append("Updated rule: {0}".format(os.path.join(target_dir, name)))
    for name in removed:
        messages.append("Removed stale rule (backed up): {0}".format(os.path.join(target_dir, name)))

    return True, messages


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="plugin rules/ directory")
    parser.add_argument("--target", required=True, help="destination .cursor/rules directory")
    args = parser.parse_args(argv)

    source_dir = os.path.abspath(args.source)
    target_dir = os.path.abspath(args.target)

    if not os.path.isdir(source_dir):
        print("ERROR: source is not a directory: {0}".format(source_dir), file=sys.stderr)
        return 1

    if os.path.exists(target_dir) and not os.path.isdir(target_dir):
        print(
            "ERROR: {0} exists but is not a directory. Leaving it untouched — "
            "fix or remove it, then re-run.".format(target_dir),
            file=sys.stderr,
        )
        return 1

    _, messages = install_rules(source_dir, target_dir)
    for line in messages:
        if line.startswith("WARNING:"):
            print(line, file=sys.stderr)
        else:
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
