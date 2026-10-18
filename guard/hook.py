#!/usr/bin/env python3
"""PreToolUse hook entrypoint for the sink-guard.

Claude Code invokes this with the tool-call event as JSON on stdin. We classify
the Bash command and emit a `hookSpecificOutput.permissionDecision` of:

    "ask"   -> force a human prompt, overriding any allowlist auto-approve.
    "deny"  -> block outright (only in enforce mode).
    (none)  -> stay silent so the normal permission flow proceeds.

MODE (env GUARD_MODE, default "ask-default"):
    "ask-default" -- FIRST-LANDING, SAFE. A policy 'deny' is downgraded to
                     'ask'. Nothing legit is ever auto-blocked; every flagged
                     command becomes a prompt you can approve. Chosen because a
                     false positive costs a prompt, never a blocked task.
    "enforce"     -- a policy 'deny' is emitted as 'deny' (auto-block). Only
                     promote to this after a second blind held-out eval and
                     real-session friction data justify it (see Stage 0 writeup).

Fail-safe, never fail-open-silently: if anything throws, we emit 'ask' with the
error as the reason and log it. A broken guard degrades to "ask the human",
never to "silently allow" and never to a swallowed exception.

Only Bash is in scope (the matcher should ensure this; we double-check).
"""
from __future__ import annotations

import datetime
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_LOG = os.path.join(os.path.dirname(_HERE), "logs", "decisions.jsonl")

sys.path.insert(0, _HERE)
from policy import classify  # noqa: E402


def _log(record: dict) -> None:
    """Append one decision record. Logging must never break the hook."""
    try:
        os.makedirs(os.path.dirname(_LOG), exist_ok=True)
        with open(_LOG, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        # Can't log -> say so on stderr, but do not fail the tool call.
        print(f"sink-guard: could not write log: {exc}", file=sys.stderr)


def _emit(decision: str | None, reason: str) -> None:
    """Emit a permission decision, or nothing to defer to normal flow."""
    if decision is None:
        return
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))


def main() -> int:
    mode = os.environ.get("GUARD_MODE", "ask-default")
    raw = sys.stdin.read()

    try:
        event = json.loads(raw)
    except json.JSONDecodeError as exc:
        # Blind to the event -> ask the human, and surface it.
        _log({"ts": datetime.datetime.now().isoformat(), "error": f"bad-json: {exc}",
              "raw": raw[:2000], "emitted": "ask"})
        _emit("ask", f"sink-guard could not parse the tool event ({exc}); "
                     "asking for confirmation.")
        return 0

    tool = event.get("tool_name")
    command = (event.get("tool_input") or {}).get("command", "")

    # Out of scope -> stay silent, let normal flow handle it.
    if tool != "Bash" or not command.strip():
        return 0

    try:
        policy_decision, reason = classify(command)
    except Exception as exc:  # noqa: BLE001 - fail-safe, but never silent
        _log({"ts": datetime.datetime.now().isoformat(), "error": f"policy-raised: {exc!r}",
              "command": command, "emitted": "ask"})
        _emit("ask", f"sink-guard policy errored ({exc!r}); asking for confirmation.")
        return 0

    # Map policy result -> emitted decision, per mode.
    if policy_decision == "allow":
        emitted = None
    elif policy_decision == "ask":
        emitted = "ask"
    else:  # policy 'deny'
        emitted = "deny" if mode == "enforce" else "ask"

    _log({
        "ts": datetime.datetime.now().isoformat(),
        "session_id": event.get("session_id"),
        "cwd": event.get("cwd"),
        "mode": mode,
        "command": command,
        "policy_decision": policy_decision,
        "emitted": emitted or "allow(defer)",
        "reason": reason,
    })

    prefix = "sink-guard" + (" [would BLOCK in enforce mode]"
                             if policy_decision == "deny" and mode != "enforce" else "")
    _emit(emitted, f"{prefix}: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
