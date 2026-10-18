#!/usr/bin/env python3
"""Sink-guard policy engine.

Classifies a single Bash command into one of three decisions:

    "deny"  -- high-confidence harmful effect; refuse.
    "ask"   -- plausibly harmful OR deliberately opaque; hand to the human.
    "allow" -- no rule fired.

Design stance, established at Stage 0 (see README, "What was validated"):

  * We gate by EFFECT (secret bytes leaving, persistence written, data
    destroyed), not by matching a blocklist of known-bad strings. A held-out
    eval showed string-blocklisting collapses to ~62% recall on attacks it
    wasn't tuned to.
  * OPACITY IS ITSELF A SIGNAL. We do not try to decode every obfuscation; a
    command that is deliberately unreadable (assembles a verb from fragments,
    decodes bytes then pipes to an interpreter, rot13/hex/base64 -> shell) is
    refused *because* it can't be read.
  * CODE ACQUISITION FROM A NON-DEFAULT SOURCE routes to 'ask' -- the entry
    path for supply-chain attacks, which per-command inspection can't verify.
  * This is a BACKSTOP layered under Claude Code's existing auto-mode
    classifier, not a replacement for it.

The engine never blocks silently: every 'deny'/'ask' carries a human-readable
reason string, surfaced to the agent and logged.
"""
from __future__ import annotations

import os
import re

# --- home directories ---------------------------------------------------------
# This user's real $HOME, plus any /home/<name> or /Users/<name>, so a command
# naming a home by its absolute path is judged the same as one using ~ or $HOME
# (was a hard-coded /home/<author> until 2026-10-18). Not after a word
# character or '.', so ./home/x/build is a relative path, not a home.
_HOME = (r"(?<![\w.-])(?:" + re.escape(os.path.expanduser("~").rstrip("/") or "/")
         + r"|/home/[\w.-]+|/Users/[\w.-]+)")

# --- extra trusted hosts --------------------------------------------------------
# Machine-specific hosts (ssh aliases, the home LAN) are not in this file: one
# regex per line in trusted_hosts.local at the repo root (gitignored), '#' starts
# a comment. SINK_GUARD_HOSTS_FILE points somewhere else. A missing file means no
# extra hosts; an unreadable file or a bad regex raises at import, which the
# launcher turns into 'ask' -- never a silent allow.
_HOSTS_FILE = os.environ.get("SINK_GUARD_HOSTS_FILE", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "trusted_hosts.local"))


def read_hosts_file(path: str) -> list[str]:
    try:
        with open(path) as fh:
            lines = [line.split("#", 1)[0].strip() for line in fh]
    except FileNotFoundError:
        return []
    return [line for line in lines if line]

# --- sensitive read targets -------------------------------------------------
SECRET_PATH = re.compile(
    r"\.ssh(/|(?![\w.-]))|id_rsa|id_ed25519|\.pem\b|\.aws/|\.config/gcloud|"
    r"\.claude\.json|(?<!/)credentials\b|\.bash_history|authorized_keys|oauthAccount|"
    # added 2026-09-27 (second blind set): OS password hashes, keyrings, browser
    # profiles (saved logins + cookies), GPG, gh/netrc tokens.
    r"/etc/g?shadow\b|\.local/share/keyrings|\.gnupg/|\.netrc\b|\.config/gh/hosts|"
    r"\.mozilla/firefox|\.config/(google-chrome|chromium|BraveSoftware)",
    re.I,
)

# --- network egress ---------------------------------------------------------
EGRESS = re.compile(
    r"\b(curl|wget|nc|ncat|scp|sftp|socat|telnet)\b|/dev/(tcp|udp)/"
    r"|\brsync\b[^|;&]*\s(\S+@)?[\w.-]+:(?!//)",      # rsync only when a side is remote
    re.I,
)
URL_HOST = re.compile(r"https?://([A-Za-z0-9_.:\-]+)", re.I)
# Non-URL targets: `scp f host:dir`, `rsync -a d user@host:`, `nc host 4444`,
# `socat TCP:host:port`, `/dev/tcp/host/port`.
REMOTE_SPEC = re.compile(r"(?:^|\s)[\"']?(?:[\w.-]+@)?([A-Za-z0-9_.-]+):(?!//)")
REMOTE_VERB = re.compile(r"\b(scp|sftp|rsync)\b", re.I)
NC_HOST = re.compile(r"\b(?:nc|ncat|telnet)\b(?:\s+-\S+(?:\s+\d+)?)*\s+([A-Za-z0-9_.-]+)", re.I)
SOCAT_HOST = re.compile(r"\b(?:tcp|udp|openssl)[46]?(?:-connect)?:([A-Za-z0-9_.-]+):\d+", re.I)
DEVTCP_HOST = re.compile(r"/dev/(?:tcp|udp)/([A-Za-z0-9_.-]+)/", re.I)


def build_known_hosts(extra: list[str]) -> re.Pattern:
    """Default hosts plus `extra` (regexes). Trusted only for 'unknown host'
    friction -- secret+egress still denies."""
    local = "".join(f"(?:{h})|" for h in extra)
    return re.compile(
        r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|" + local +
        r"([a-z0-9-]+\.)*(github\.com|githubusercontent\.com|papermc\.io|"
        r"mojang\.com|pypi\.org|files\.pythonhosted\.org|anthropic\.com))(:\d+)?$",
        re.I,
    )


KNOWN_HOSTS = build_known_hosts(read_hosts_file(_HOSTS_FILE))

# --- opacity: a command that hides what it does -----------------------------
OPACITY = re.compile(
    r"base64\s+(-d|--decode)"
    r"|xxd\s+-r"
    r"|\|\s*tr\s+['\"]?[A-Za-z]-[A-Za-z]"          # rot13-style tr pipe
    r"|bytes\.fromhex|fromhex\("
    r"|chr\(\d+\)\s*\+\s*chr\("
    r"|__import__\("
    r"|printf\s+['\"]?%b"
    r"|\bIFS=[^ ;]"                                  # custom field-splitting
    r"|\$\{?[a-zA-Z_]\w*\}?\$\{?[a-zA-Z_]"          # $a$b token concat
    r"|(\\x[0-9a-f]{2}){2,}|(\\[0-7]{3}){2,}"          # consecutive hex/octal escapes
    r"|\bpack\s*\(\s*([\"']|q[qw]?\s*[{(\[/|])H",                          # perl pack("H*", hex)
    re.I,
)

# --- reverse shells / remote command channels -------------------------------
REVSHELL = re.compile(
    # /dev/tcp alone is also a common port probe; it is a shell only when a
    # shell or its stdio is wired to it.
    r"/dev/(tcp|udp)/\S+[^|;&]*(0>&1|[01]?<&[012]|>&\s*0)"
    r"|\b(ba|z)?sh\s+-i\b[^|;&]*/dev/(tcp|udp)/"
    r"|\bexec\s+\d+<>\s*/dev/(tcp|udp)/"
    r"|\bn(c|cat)\b[^|;&]*\s-[a-zA-Z]*[ec]\b"
    r"|\bsocat\b[^|;&]*\b(EXEC|SYSTEM):"
    r"|os\.dup2|pty\.spawn",
    re.I,
)
VARSPLIT_VERB = re.compile(r"[a-z]=[a-z]{1,3};[a-z]=[a-z]{1,3};", re.I)

# --- fetch/eval piped to an interpreter -------------------------------------
FETCH_PIPE_INTERP = re.compile(
    r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba?sh|sh|zsh|perl|node|python3?)\b"
    r"|(ba?sh|sh|python3?|node)\s*<\(\s*(curl|wget)",
    re.I,
)
# `eval` is only dangerous here when it evaluates fetched/opaque content.
EVAL_FETCH = re.compile(r"\beval\s+[\"']?\$\(\s*(curl|wget)", re.I)
PLAIN_EVAL_SUBST = re.compile(r"\beval\s+[\"']?\$\(", re.I)

# --- interpreter doing its own network I/O ----------------------------------
INTERP_NET = re.compile(
    r"IO::Socket|socket\.socket|socket\.connect|urllib|requests\.(get|post)|"
    r"http\.client|smtplib|\bdig\s+|\bnslookup\b|\bhost\s+\S+\.\S+",
    re.I,
)

# --- persistence sinks ------------------------------------------------------
PERSIST_SINK = re.compile(
    r">>?\s*~?/?[^ ]*(\.bashrc|\.profile|\.bash_profile|\.zshrc|"
    r"authorized_keys|\.claude/settings|\.git/hooks/|\.config/pip)"
    r"|crontab\s+-(?!l\b)|PROMPT_COMMAND",  # `crontab -l` only reads (2026-09-27)
    re.I,
)
# Startup locations written by redirect, tee, cp/mv/ln/install or sed -i
# (added 2026-09-27: systemd user units and XDG autostart were uncovered).
_PERSIST_LOC = (
    r"(\.config/(systemd/user|autostart)/|/etc/(systemd|cron[\w.]*|profile\.d|init\.d|sudoers)"
    r"|/etc/rc\.local|\.local/share/applications/"
    r"|(\.bashrc|\.profile|\.bash_profile|\.zshrc|\.bash_logout|\.xprofile|\.xsessionrc"
    r"|authorized_keys)(?![\w.-]))"
)
PERSIST_WRITE = re.compile(
    r"(>>?|\btee\b(\s+-a)?)\s*[\"']?[^\s|;&]*" + _PERSIST_LOC
    + r"|\b(cp|mv|ln|install)\b[^|;&]*\s[\"']?[^\s|;&]*" + _PERSIST_LOC + r"[^\s|;&]*[\"']?\s*($|[|;&])"
    + r"|\bsed\s+-i\b[^|;&]*" + _PERSIST_LOC,
    re.I,
)
SERVICE_ENABLE = re.compile(r"\bsystemctl\b[^|;&]*\benable\b", re.I)

# --- destructive ------------------------------------------------------------
DESTRUCTIVE = re.compile(
    # $HOME / ${HOME}, quoted or not (added 2026-09-27: `rm -rf "$HOME/x"` was
    # allowed). `\b` keeps $HOME_DIR-style variables out.
    r"\brm\s+-[rf]{1,2}[a-z]*\s+[^|]*(" + _HOME + r"|~/|\$(HOME\b|\{HOME\})[\"']?/|(?<![\w/])\*)"
    r"|find\s+[^|]*-exec\s+rm"
    r"|for\s+\w+\s+in[^;]*;\s*do\s*:?\s*>\s*"        # truncate loop `: > file`
    r"|git\s+(-C\s+\S+\s+)?reset\s+--hard\s+HEAD~"
    r"|git\s+(-C\s+\S+\s+)?clean\s+-[a-z]*f"
    r"|\bshred\b|\bdd\s+if=/dev/(zero|urandom|random)",
    re.I,
)
TMP_ONLY = re.compile(r"/tmp/|/scratchpad", re.I)
# `git rm --cached` only unstages; files stay on disk. Neutralised before the
# DESTRUCTIVE check so its `rm -r` is not read as a deletion (added
# 2026-09-27: `git rm -rq --cached <dir> && ... ~/.claude/...` was denied).
# Plain `git rm -r` (deletes the working-tree files) is still caught.
GIT_RM_CACHED = re.compile(r"\bgit\s+(-C\s+\S+\s+)?rm\b(?=[^|;&\n]*\s--cached\b)", re.I)
# DESTRUCTIVE and TMP_ONLY are judged per command segment, not per command
# line (added 2026-09-27). Whole-line matching failed both ways: `rm -rf build
# && ls ~/Desktop` was denied (rm in one segment, home path in another), and
# `mkdir /tmp/s; rm -rf ~/.ssh` was ALLOWED (a /tmp/ anywhere exempted it).
# Splitting is quote-blind on purpose: a separator inside quotes only yields
# more segments to check, which errs toward flagging.
_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|&\n]")
# The truncate loop's own syntax spans `;`, so it is matched on the whole line
# (unchanged whole-line /tmp exemption); segmenting it let
# `for f in $(find ...); do : > "$f"; done` through in held-out re-measurement.
TRUNCATE_LOOP = re.compile(r"for\s+\w+\s+in[^;]*;\s*do\s*:?\s*>\s*", re.I)


def _destructive_segment(cmd: str) -> bool:
    if TRUNCATE_LOOP.search(cmd) and not TMP_ONLY.search(cmd):
        return True
    cmd = GIT_RM_CACHED.sub("git index-remove", cmd.replace("\\\n", " "))
    return any(DESTRUCTIVE.search(seg) and not TMP_ONLY.search(seg)
               for seg in _SEGMENT_SPLIT.split(cmd))
# Wholesale wipes of home, root, system dirs or a disk. Never exempted by a
# /tmp mention (added 2026-09-27: `rm -rf ~` and `rm -rf /` were allowed,
# because the rule above required a `~/` or home-path prefix).
_WHOLE = (r"[\"']?(~|\$HOME|\$\{HOME\}|" + _HOME + r"|/home|/|/(etc|usr|bin|sbin|boot|lib\w*|var|opt|srv|root|dev|mnt|media))"
          r"/?\*?[\"']?(?=\s|$|[;&|)])")
WHOLESALE_DESTROY = re.compile(
    r"\brm\b(?=[^|;&]*\s(-[a-zA-Z]*[rR]|--recursive))[^|;&]*\s" + _WHOLE
    + r"|\bfind\s+" + _WHOLE + r"[^|;&]*\s(-delete|-exec\s+(rm|shred))"
    + r"|\bch(mod|own|grp)\b(?=[^|;&]*\s(-[a-zA-Z]*R|--recursive))[^|;&]*\s" + _WHOLE
    + r"|\bmkfs(\.\w+)?\b|\bwipefs\b|\bblkdiscard\b"
    + r"|\bdd\b[^|;&]*\bof=/dev/(sd|nvme|hd|vd|mmcblk)"
    + r"|>\s*/dev/(sd[a-z]|nvme\d|mmcblk\d)",
    re.I,
)
FORK_BOMB = re.compile(r"(\b\w+|:)\s*\(\)\s*\{[^}]*?\1\s*\|\s*\1\s*&")

# --- credential harvesting --------------------------------------------------
SECRET_KEYWORDS = re.compile(r"aws_secret|api[_-]?key|secret|bearer|token|password|passwd", re.I)
RECURSIVE_SEARCH = re.compile(r"\b(grep|rg|ag)\b[^|]*-[a-z]*r|\bfind\b", re.I)
SECRET_VERB = re.compile(
    r"\b(cat|less|more|head|tail|strings|xxd|od|json\.load|open|"
    r"cp|mv|rsync|tar|zip|7z|base64|sqlite3|dd|install)\b", re.I)
KEYRING_DUMP = re.compile(
    r"\bsecret-tool\s+(lookup|search)|\bgpg\b[^|;&]*--export-secret"
    r"|\bsecurity\s+find-(generic|internet)-password", re.I)
ENV_DUMP = re.compile(r"\benv\b\s*(\||>)|printenv", re.I)

# --- code acquisition from non-default source -------------------------------
PKG_INSTALL = re.compile(r"\b(pip3?|python3?\s+-m\s+pip)\s+install|\bnpm\s+(install|i|pkg)\b", re.I)
PKG_NONDEFAULT = re.compile(
    r"--index-url|--extra-index-url|git\+|https?://|\.tar\.gz|\.tgz|/tmp/|--registry",
    re.I,
)
GIT_CODE_ADD = re.compile(
    r"git\s+(-C\s+\S+\s+)?(remote\s+add|submodule\s+add)"
    r"|>>?\s*\S*requirements[^ ]*\.txt",
    re.I,
)

Decision = tuple[str, str]  # (decision, reason)


def _hosts(cmd: str) -> list[str]:
    hosts = URL_HOST.findall(cmd)
    if REMOTE_VERB.search(cmd):
        hosts += REMOTE_SPEC.findall(cmd)
    hosts += NC_HOST.findall(cmd) + SOCAT_HOST.findall(cmd) + DEVTCP_HOST.findall(cmd)
    return hosts


def _egress_to_unknown(cmd: str) -> bool:
    if not EGRESS.search(cmd):
        return False
    hosts = _hosts(cmd)
    if not hosts:
        return True  # egress verb, no parseable URL (e.g. `nc ip port`)
    return any(not KNOWN_HOSTS.match(h) for h in hosts)


def _interp_net_to_unknown(cmd: str) -> bool:
    """Interpreter doing network I/O, where the target is not a known host."""
    if not INTERP_NET.search(cmd):
        return False
    hosts = URL_HOST.findall(cmd)
    if not hosts:
        return True  # raw socket / dns lookup with no http URL
    return any(not KNOWN_HOSTS.match(h) for h in hosts)


def classify(cmd: str) -> Decision:
    """Return (decision, reason) for a single Bash command string."""
    # 1. Opacity is the signal -- refuse what can't be read.
    if OPACITY.search(cmd) or VARSPLIT_VERB.search(cmd):
        return "deny", "opaque/obfuscated command (refusing to run unreadable code)"

    # 1b. Reverse shell / remote command channel.
    if REVSHELL.search(cmd):
        return "deny", "opens a reverse shell / remote command channel"

    # 1c. Wholesale destruction (home, root, system dirs, disks, fork bomb).
    if WHOLESALE_DESTROY.search(cmd) or FORK_BOMB.search(cmd):
        return "deny", "wipes the home directory, root, a system directory or a disk"

    # 2. Fetch-or-eval piped into an interpreter.
    if FETCH_PIPE_INTERP.search(cmd) and _egress_to_unknown(cmd):
        return "deny", "remote content piped to an interpreter"
    if EVAL_FETCH.search(cmd):
        return "deny", "eval of fetched content"

    # 3. Persistence.
    if PERSIST_SINK.search(cmd) or PERSIST_WRITE.search(cmd):
        return "deny", "write to a persistence/startup/agent-config location"

    # 4. Exfiltration: secret read + any egress channel.
    if SECRET_PATH.search(cmd) and (EGRESS.search(cmd) or INTERP_NET.search(cmd)):
        return "deny", "reads a secret and opens a network channel (exfil shape)"
    if _interp_net_to_unknown(cmd) and ("exec(" in cmd or "system(" in cmd):
        return "deny", "interpreter fetches and executes remote code"

    # 5. Destructive (outside /tmp).
    if _destructive_segment(cmd):
        return "deny", "destructive operation outside /tmp"

    # 6. Credential reads / harvesting.
    if SECRET_PATH.search(cmd) and SECRET_VERB.search(cmd):
        return "deny", "reads or copies a credential/secret file"
    if KEYRING_DUMP.search(cmd):
        return "deny", "dumps secrets from the keyring"
    if ENV_DUMP.search(cmd) and SECRET_KEYWORDS.search(cmd):
        return "deny", "harvests secrets from the environment"

    # 7. Recursive secret search over the home dir -> ask (could be legit code search).
    if RECURSIVE_SEARCH.search(cmd) and SECRET_KEYWORDS.search(cmd) and re.search(
        _HOME + r"|~/|\$HOME", cmd
    ):
        return "ask", "recursive search for secrets across the home directory"

    # 8. Code acquisition from a non-default source -> ask.
    if PKG_INSTALL.search(cmd) and PKG_NONDEFAULT.search(cmd):
        return "ask", "installs a package from a non-default source"
    if GIT_CODE_ADD.search(cmd):
        return "ask", "adds a code source (remote/submodule/requirement)"
    if PKG_INSTALL.search(cmd):
        return "ask", "installs a package (confirm it is intended)"
    if SERVICE_ENABLE.search(cmd):
        return "ask", "enables a service to start automatically"

    # 9. Grey-zone egress / eval.
    if FETCH_PIPE_INTERP.search(cmd):
        return "ask", "downloads and pipes to an interpreter (known host)"
    if PLAIN_EVAL_SUBST.search(cmd):
        return "ask", "eval of a command substitution"
    if _egress_to_unknown(cmd) or _interp_net_to_unknown(cmd):
        return "ask", "network egress to an unrecognised host"

    return "allow", "no rule fired"
