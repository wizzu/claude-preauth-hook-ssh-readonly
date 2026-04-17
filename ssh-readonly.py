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
    # Git inspection (read-only subcommands only; branch/tag/remote/commit/push etc. fall through)
    # Handles git-level flags before the subcommand (e.g. git -C /path log, git --no-pager diff)
    # Excludes branch/tag/remote/config: those have write forms that share the same subcommand name
    (
        r"git(\s+(-C\s+\S+|--git-dir=\S+|--work-tree=\S+|--no-pager|-p|--paginate))*\s+"
        r"(status|log|diff|show|blame|shortlog|describe"
        r"|ls-files|ls-tree|cat-file|grep"
        r"|rev-parse|rev-list|for-each-ref"
        r"|stash\s+list)"
    ),
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
readonly_re = re.compile(rf"^(sudo(\s+-\S+)*\s+)?({_combined})\b", re.DOTALL)

_unsafe_combined = "|".join(f"(?:{p})" for p in UNSAFE_PATTERNS)
unsafe_re = re.compile(_unsafe_combined, re.DOTALL)


def decide(command: str, allowed_host: str | None) -> str | None:
    """Classify an SSH command for the pre-tool-use hook.

    Returns:
        "allow"  — read-only command on the configured host; auto-approve.
        "ask"    — potentially destructive command on the configured host; block.
        None     — outside the hook's scope (no host configured, wrong host, not SSH);
                   defer to Claude Code's default permissions.
    """
    if not allowed_host:
        return None

    m = re.match(r'^ssh\s+(\S+)\s+(?:"(.+)"|\'(.+)\'|(.+))$', command, re.DOTALL)
    if not m:
        return None

    host = m.group(1)
    inner = (m.group(2) or m.group(3) or m.group(4)).strip()

    if host != allowed_host:
        return None

    if readonly_re.match(inner) and not unsafe_re.search(inner):
        return "allow"
    return "ask"


def main() -> None:
    allowed_host = sys.argv[1] if len(sys.argv) > 1 else None

    data = json.load(sys.stdin)
    cmd = data.get("tool_input", {}).get("command", "")

    result = decide(cmd, allowed_host)

    _debug_log = os.path.expanduser("~/.claude/hooks/ssh-readonly-debug.log")
    if os.path.exists(_debug_log):
        m = re.match(r'^ssh\s+(\S+)\s+(?:"(.+)"|\'(.+)\'|(.+))$', cmd, re.DOTALL)
        if m:
            host = m.group(1)
            inner = (m.group(2) or m.group(3) or m.group(4)).strip()
            with open(_debug_log, "a") as f:
                f.write(f"cmd={cmd!r}\nhost={host!r}\ninner={inner!r}\ndecision={result!r}\n---\n")

    if result is None:
        sys.exit(0)  # Defer to Claude Code's default permissions

    if result == "allow":
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": (
                            f"Read-only ssh {allowed_host} command auto-approved"
                        ),
                    }
                }
            )
        )
    else:
        print(
            json.dumps(
                {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}}
            )
        )

    sys.exit(0)


if __name__ == "__main__":
    main()
