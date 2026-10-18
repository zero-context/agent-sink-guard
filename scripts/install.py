#!/usr/bin/env python3
"""Opt-in installer for the sink-guard PreToolUse hook.

Adds (or removes) the guard's hook entry in a Claude Code settings.json. It:
  - backs the file up first (settings.json.guard-bak),
  - is idempotent (re-running does not duplicate the entry),
  - refuses to touch a pre-existing Bash PreToolUse hook it did not create,
  - reverses cleanly with --uninstall.

Usage:
    python3 scripts/install.py                 # ~/.claude/settings.json
    python3 scripts/install.py --project DIR    # DIR/.claude/settings.json
    python3 scripts/install.py --uninstall
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

GUARD_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK_CMD = f"python3 {os.path.join(GUARD_DIR, 'guard', 'hook.py')}"
MARKER = "agent-sink-guard"  # identifies entries we own


def _hook_entry() -> dict:
    return {
        "matcher": "Bash",
        "_source": MARKER,
        "hooks": [{"type": "command", "command": HOOK_CMD}],
    }


def _settings_path(args) -> str:
    if args.project:
        return os.path.join(os.path.abspath(args.project), ".claude", "settings.json")
    return os.path.expanduser("~/.claude/settings.json")


def _load(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        return json.load(fh)


def _backup(path: str) -> None:
    if os.path.exists(path):
        bak = path + ".guard-bak"
        shutil.copy2(path, bak)
        print(f"  backed up existing settings -> {bak}")


def _pretooluse_list(settings: dict) -> list:
    return settings.setdefault("hooks", {}).setdefault("PreToolUse", [])


def install(path: str) -> int:
    settings = _load(path)
    entries = _pretooluse_list(settings)

    for e in entries:
        if e.get("_source") == MARKER:
            print("  already installed; nothing to do.")
            return 0
        # A Bash PreToolUse hook we did not create -> do not silently stack on it.
        if e.get("matcher") == "Bash" and e.get("_source") != MARKER:
            print("  WARNING: an existing Bash PreToolUse hook is present that "
                  "this installer did not create.", file=sys.stderr)
            print("  Refusing to modify it automatically. Add this hook command "
                  "manually if you want both:\n    " + HOOK_CMD, file=sys.stderr)
            return 3

    os.makedirs(os.path.dirname(path), exist_ok=True)
    _backup(path)
    entries.append(_hook_entry())
    with open(path, "w") as fh:
        json.dump(settings, fh, indent=2)
    print(f"  installed sink-guard hook in {path}")
    print("  mode: ask-default (set GUARD_MODE=enforce to auto-block denies)")
    return 0


def uninstall(path: str) -> int:
    if not os.path.exists(path):
        print(f"  {path} does not exist; nothing to remove.")
        return 0
    settings = _load(path)
    entries = settings.get("hooks", {}).get("PreToolUse", [])
    kept = [e for e in entries if e.get("_source") != MARKER]
    if len(kept) == len(entries):
        print("  no sink-guard entry found; nothing to remove.")
        return 0
    _backup(path)
    settings["hooks"]["PreToolUse"] = kept
    if not settings["hooks"]["PreToolUse"]:
        del settings["hooks"]["PreToolUse"]
    if not settings["hooks"]:
        del settings["hooks"]
    with open(path, "w") as fh:
        json.dump(settings, fh, indent=2)
    print(f"  removed sink-guard hook from {path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", metavar="DIR", help="install into DIR/.claude/settings.json")
    ap.add_argument("--uninstall", action="store_true")
    args = ap.parse_args()
    path = _settings_path(args)
    print(f"target: {path}")
    return uninstall(path) if args.uninstall else install(path)


if __name__ == "__main__":
    sys.exit(main())
