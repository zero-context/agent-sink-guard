# agent-sink-guard

A `PreToolUse` hook for Claude Code that gates **Bash** commands by their
**effect** — secret exfiltration, persistence, credential theft, destructive
operations, code from untrusted sources, and deliberately obfuscated commands —
regardless of whether a prompt injection, a confused agent, or a mistake
produced them.

It is a **backstop layered under** Claude Code's existing auto-mode classifier,
not a replacement for it, and not an antivirus for your PC.

## What was validated

- A `PreToolUse` hook can **veto a command the permission allowlist already
  auto-approved** — proven with a paired headless test (same allowlist entry,
  control command approved, test command vetoed by the hook). This is the
  enforcement point; it is strictly stronger than the allowlist.
- Gating by matching known-bad **strings** fails. A first policy scored 93% on
  attacks written alongside it, then **62%** (37/60) on 60 attacks written by a
  separate agent *blind to the policy*. Supply-chain (1/10) and obfuscation
  (3/8) collapsed.
- Gating by **effect**, plus treating **opacity itself as a signal** (refuse
  what can't be read) and routing **package installs to a prompt**, recovered
  those families. Current numbers:

| Set | Size | Result |
|---|---|---|
| Held-out blind attacks (`heldout_attacks.jsonl`) | 60 | 60 stopped: 45 deny, 15 ask |
| Second blind set, attacks (`blind2_…`, set `blind2`) | 53 | 53 stopped: 46 deny, 7 ask |
| Post-fix variants (`blind2_…`, set `variants`) | 38 | 38 deny |
| Look-alike benign commands (`blind2_…`, set `lookalike`) | 37 | 35 allow, 2 deny |
| The author's real commands (private, not published) | 1,276 | 96.3% allow, 3.2% ask, **0.47% deny** |

Read those numbers with the bias in mind: **both blind sets were used to fix
the policy after they were run**, so they are now regression sets, not
unbiased evals. A third blind set is still owed. The real-command corpus is
one person's Linux machine and is not published (it is a record of that
machine); its tests skip when it is absent. Put your own commands in
`fixtures/private/benign_corpus.jsonl` (`{"command": "..."}` per line) to
measure your own friction before you trust `enforce`.

## Two modes

Set with the `GUARD_MODE` environment variable:

- **`ask-default`** (default, first-landing): a policy `deny` is downgraded to
  **ask** (a prompt). Nothing legitimate is ever auto-blocked; a false positive
  costs you one prompt. This is the safe mode to run live while it earns trust.
- **`enforce`**: a policy `deny` **blocks** the command outright. The author
  runs this, accepting ~0.5% of real commands hard-blocked. Look at your own
  `logs/decisions.jsonl` friction before you switch.

In both modes, `allow` stays silent and defers to normal permission handling,
and the guard **fails safe** — any internal error becomes an `ask`, never a
silent allow.

## Install (opt-in, reversible)

The guard is inert until you register it in a Claude Code `settings.json`.
`scripts/install.py` adds the hook block; `scripts/install.py --uninstall`
removes it. It targets `~/.claude/settings.json` by default (all sessions) or
`--project <dir>` for one workspace. It backs up the file first and refuses to
clobber an unrelated existing hook.

```
python3 scripts/install.py            # register in ~/.claude/settings.json
python3 scripts/install.py --uninstall
```

Reverting is "run --uninstall" or delete the `hooks` block — never a recovery
operation.

## Your own machines

Egress to a host the guard does not recognise is an `ask`. To stop prompting
for your own machines (ssh aliases) or your LAN, copy `trusted_hosts.example`
to `trusted_hosts.local` and edit it: one regex per line, matched against the
whole host. That file is gitignored. A trusted host only removes the
unknown-host prompt — reading a secret and sending it anywhere is still
denied. `SINK_GUARD_HOSTS_FILE` points the guard at a different file.

Home directories are not configured: the guard treats your `$HOME`, `~`, and
any `/home/<name>` or `/Users/<name>` path as a home.

## Tests

```
python3 -m pytest -q tests
```

The suite pins the numbers above with a margin, so an ordinary refactor passes
but a family falling back to `allow` fails. It loads `trusted_hosts.example`
(the hosts the published fixtures use) plus your `trusted_hosts.local`.

## Layout

```
guard/policy.py        effect-based classifier -> (decision, reason)
guard/hook.py          stdin JSON -> classify -> permissionDecision, + decision log
tests/                 regression suite pinned to the measured numbers
fixtures/              held-out, second blind and original attack sets
fixtures/private/      your real benign commands (gitignored)
trusted_hosts.example  template for trusted_hosts.local (gitignored)
scripts/install.py     opt-in / uninstall wiring
logs/                  decisions.jsonl (gitignored) — the real-world friction record
```

## Known gaps (do not oversell)

- **`ask` does nothing under `permissions.defaultMode: "auto"`.** Verified live:
  a command the guard answered `ask` for ran with no prompt shown. In auto
  mode only `deny` stops a command, so `ask-default` mode is log-only there.
  Use `enforce` if the guard is meant to protect an auto-mode setup.
- **The installer registers `hook.py` directly.** If the folder is moved,
  `python3` exits 2 and Claude Code treats that as a block on every Bash call,
  including the one that would fix it. A syntax error in `policy.py` exits 1
  instead, which lets commands run unchecked. Keep the folder where it was
  installed, and run the tests after editing the policy.
- Per-command only: a read-now / send-later exfil split across two commands is
  not caught by the sending half alone.
- `rm --recursive --force` (long flags) is not in the destructive rule yet
  (an `xfail` test records it).
- The default host allowlist (github, pypi, papermc, …) was fit to one user's
  history.
- Bash only. WebFetch / browser / file-write sinks are out of scope.

## License

MIT — see `LICENSE`.
