#!/usr/bin/env python3
import json
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
# --- End config ---

# Build combined pattern from the list above
_combined = "|".join(f"(?:{p})" for p in READONLY_COMMANDS)
readonly_re = re.compile(rf"^(sudo\s+)?({_combined})\b", re.DOTALL)

# -- Rest of script unchanged --

allowed_host = sys.argv[1] if len(sys.argv) > 1 else None

data = json.load(sys.stdin)
cmd = data.get("tool_input", {}).get("command", "")

ask = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}})

if not allowed_host:
    print(ask); sys.exit(0)

m = re.match(r'^ssh\s+(\S+)\s+(?:"(.+)"|\'(.+)\'|(.+))$', cmd, re.DOTALL)
if not m:
    print(ask); sys.exit(0)

host = m.group(1)
inner = (m.group(2) or m.group(3) or m.group(4)).strip()

if host != allowed_host:
    print(ask); sys.exit(0)

if readonly_re.match(inner):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": f"Read-only ssh {host} command auto-approved"}}))
else:
    print(ask)

sys.exit(0)
