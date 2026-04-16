#!/usr/bin/env python3
import json
import os
import re
import sys

# --- Config: read-only command patterns ---
# Each entry is a regex matched against the inner SSH command (after optional "sudo ").
# Simple command names match anywhere they appear as the first word.
READONLY_COMMANDS = [
    # File reading
    r"cat",
    r"head",
    r"tail",
    r"less",
    r"file",
    # Directory / file listing
    r"ls",
    r"ll",
    r"la",
    r"find",
    r"stat",
    r"readlink",
    r"realpath",
    # Search
    r"grep",
    r"rgrep",
    # Disk / filesystem info
    r"df",
    r"du",
    r"lsblk",
    r"blkid",
    r"findmnt",
    r"fdisk\s+-l",
    r"smartctl\s+-a",
    # Process / system info
    r"ps",
    r"lsof",
    r"uname",
    r"hostname",
    r"uptime",
    r"free",
    r"dmesg",
    # Network info (read-only subcommands only)
    r"ss",
    r"netstat",
    r"ip\s+(addr|address|link|route|neigh|rule|netns)(\s+(show|list|ls).*)?",
    # Service status (not start/stop/restart)
    r"systemctl\s+status",
    r"journalctl",
    # Container inspection (read-only subcommands only; exec/run/rm/stop/etc. fall through)
    (
        r"docker\s+(ps|images|inspect|logs|stats|history|port|top|diff|info|version"
        r"|system\s+df"
        r"|network\s+(ls|list|inspect)"
        r"|volume\s+(ls|list|inspect)"
        r"|image\s+(ls|list|inspect|history)"
        r"|container\s+(ls|list|ps|inspect|logs|top|stats|port|diff)"
        r"|compose\s+(ps|logs|config|images|top|port))"
    ),
    r"docker-compose\s+(ps|logs|config|images|top|port)",
    # Text processing (used in pipelines)
    r"awk",
    r"sed",
    r"sort",
    r"uniq",
    r"cut",
    r"tr",
    r"wc",
    r"diff",
    # Checksums
    r"md5sum",
    r"sha1sum",
    r"sha256sum",
    # Misc
    r"echo",
    r"pwd",
    r"id",
    r"whoami",
    r"date",
    r"env",
    r"printenv",
    r"which",
]

# --- Config: patterns that block an otherwise-approved command ---
# Checked after the allowlist: if any match, the command is not auto-approved.
# Patterns are matched globally against the full inner command, not scoped to
# specific allowlisted commands. This is intentional: every entry here is
# unsafe regardless of context (redirection always writes, -exec always runs
# arbitrary commands, etc.). Exception: the ip pattern is scoped to \bip\b to
# avoid false positives, since words like "set" or "add" appear legitimately
# in other commands (e.g. grep arguments, awk output).
UNSAFE_PATTERNS = [
    r"(?:^|\s)\d*>>?\s",  # output redirection (>, >>, 2>, 2>>)
    r"\s-exec\b",  # find -exec
    r"\s-delete\b",  # find -delete
    r"\s-remove\b",  # find -remove
    r"[|;]\s*tee\b",  # tee in a pipeline (always writes)
    r"\bsed\b.*\s-[a-zA-Z]*i",  # sed -i / -ni / -i.bak (in-place edit)
    r"\bip\b.*\s+(set|add|del|delete|flush|change|replace|append)\b",  # ip write operations
]
# --- End config ---

# Build combined pattern from the list above
_combined = "|".join(f"(?:{p})" for p in READONLY_COMMANDS)
readonly_re = re.compile(rf"^(sudo\s+)?({_combined})\b", re.DOTALL)

_unsafe_combined = "|".join(f"(?:{p})" for p in UNSAFE_PATTERNS)
unsafe_re = re.compile(_unsafe_combined, re.DOTALL)

# -- Rest of script unchanged --

allowed_host = sys.argv[1] if len(sys.argv) > 1 else None

data = json.load(sys.stdin)
cmd = data.get("tool_input", {}).get("command", "")

ask = json.dumps(
    {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}}
)

if not allowed_host:
    sys.exit(0)  # No configured host — defer to Claude Code's default permissions

m = re.match(r'^ssh\s+(\S+)\s+(?:"(.+)"|\'(.+)\'|(.+))$', cmd, re.DOTALL)
if not m:
    sys.exit(0)  # Not an SSH command — defer to Claude Code's default permissions

host = m.group(1)
inner = (m.group(2) or m.group(3) or m.group(4)).strip()

_debug_log = os.path.expanduser("~/.claude/hooks/ssh-readonly-debug.log")
if os.path.exists(_debug_log):
    with open(_debug_log, "a") as _f:
        _f.write(f"cmd={cmd!r}\nhost={host!r}\ninner={inner!r}\n---\n")

if host != allowed_host:
    sys.exit(0)  # SSH to a different host — defer to Claude Code's default permissions

if readonly_re.match(inner) and not unsafe_re.search(inner):
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": f"Read-only ssh {host} command auto-approved",
                }
            }
        )
    )
else:
    print(ask)

sys.exit(0)
