#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

# Debug log: next to the script when run as a file; cwd fallback when piped to the interpreter.
_script_dir = Path(__file__).parent if "__file__" in dir() else Path()
_DEBUG_LOG = _script_dir / "ssh-readonly-debug.log"

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

# SSH flag letters that stand alone (no argument token follows).
# Source: ssh(1) — options listed without a value in their synopsis.
_SSH_NO_ARG_FLAGS = "46AaCfGgKkMNnqsTtVvXxYy"

# SSH flag letters that consume the next token as their argument.
# Source: ssh(1) — options listed with a value in their synopsis.
_SSH_WITH_ARG_FLAGS = "bcDEeFiJLlmopQRSwW"

# One SSH flag token: either a standalone cluster (last char takes no arg),
# or a cluster whose last char takes the next whitespace-separated token as its value.
# Examples: -t  -tvq  -i keyfile  -tvi keyfile  -p 2222
_SSH_FLAG = (
    rf"(?:-[A-Za-z0-9]*[{_SSH_NO_ARG_FLAGS}]"
    rf"|-[A-Za-z0-9]*[{_SSH_WITH_ARG_FLAGS}]\s+\S+)"
)
# Zero or more flag tokens (each separated by whitespace), plus optional '--' end-of-options.
_SSH_FLAGS_PREFIX = rf"(?:{_SSH_FLAG}\s+)*(?:--\s+)?"

# Matches three forms of SSH command. The dq_*/sq_* group name pairs exist only because
# Python's re module disallows reusing named groups within the same pattern; the quote
# style carries no semantic meaning for this hook. Use _parse_ssh() instead of accessing
# these groups directly.
#   host        — the SSH host/alias
#   dq_inner    — inner command (double-quoted form)
#   dq_trailing — shell tokens after closing " (double-quoted form)
#   sq_inner    — inner command (single-quoted form)
#   sq_trailing — shell tokens after closing ' (single-quoted form)
#   uq          — entire remainder (unquoted form; no quote boundary to split trailing from inner)
_SSH_RE = re.compile(
    rf"^ssh\s+{_SSH_FLAGS_PREFIX}(?P<host>\S+)\s+"
    r'(?:"(?P<dq_inner>.+?)"(?P<dq_trailing>\s.*)?'
    r"|'(?P<sq_inner>.+?)'(?P<sq_trailing>\s.*)?"
    r"|(?P<uq>.+))$",
    re.DOTALL,
)

# Trailing shell tokens that are safe to ignore: pure fd/devnull redirections that apply to the
# ssh process itself (e.g. 2>/dev/null, 2>&1). Anything else (pipes, output to real files, extra
# commands) is outside the hook's scope — defer to Claude Code rather than deciding either way.
_BENIGN_TRAILING_RE = re.compile(r"^\s*(\d*>>?(&\d+|/dev/null)\s*)+$")

# Heredoc redirection at the end of a command line: <<[-][whitespace]['"]WORD['"]
# The end-of-line anchor prevents matching << that appears inside a quoted argument
# (e.g. grep '<< marker' /log), which is not a heredoc.
_HEREDOC_RE = re.compile(r"""<<-?\s*['""]?\w+['""]?\s*$""")


def _parse_ssh(command: str) -> tuple[str, str, str | None] | None:
    """Parse an SSH command into (host, inner_cmd, trailing), or None if not a recognised form.

    inner_cmd is the command to be executed on the remote host.
    trailing is any shell tokens after the closing quote (e.g. '2>/dev/null'), or None.
    """
    m = _SSH_RE.match(command)
    if not m:
        return None
    host = m.group("host")
    if m.group("dq_inner") is not None:
        return host, m.group("dq_inner").strip(), m.group("dq_trailing")
    if m.group("sq_inner") is not None:
        return host, m.group("sq_inner").strip(), m.group("sq_trailing")
    return host, m.group("uq").strip(), None


def _decide_one(command: str, allowed_host: str) -> str | None:
    """Classify a single SSH command (no newlines).

    Returns "allow", "ask", or None (defer). Callers must ensure allowed_host
    is non-empty and that command contains no newlines.
    """
    parsed = _parse_ssh(command)
    if not parsed:
        return None

    host, inner, trailing = parsed

    if host != allowed_host:
        return None

    if trailing and not _BENIGN_TRAILING_RE.match(trailing):
        return None  # trailing shell action — not our call; defer

    if readonly_re.match(inner) and not unsafe_re.search(inner):
        return "allow"
    return "ask"


def decide(command: str, allowed_host: str | None) -> str | None:
    """Classify an SSH command for the pre-tool-use hook.

    Returns:
        "allow"  — read-only command on the configured host; auto-approve.
        "ask"    — potentially destructive command on the configured host; block.
        None     — outside the hook's scope (no host configured, wrong host, not SSH,
                   or has trailing shell tokens beyond benign fd redirections);
                   defer to Claude Code's default permissions.

    Multi-line input (commands batched in a single bash call) is split on newlines
    and each line classified independently; results are then aggregated.
    """
    if not allowed_host:
        return None

    # Split on newlines — intentionally naive rather than using a full shell parser.
    # A proper parser would handle edge cases (quoted newlines, heredocs) more
    # precisely, but at significant complexity cost for little practical gain: the
    # realistic case is two read-only commands batched into one bash call, and naive
    # splitting handles that correctly. All ambiguous cases safely defer to Claude
    # Code; a false allow is not possible.
    lines = [line.strip() for line in command.split("\n") if line.strip()]
    if not lines:
        return None

    # Heredocs can't be safely classified after a naive split (the content lines
    # would be evaluated as independent commands), so defer the whole thing.
    if any(_HEREDOC_RE.search(line) for line in lines):
        return None

    results = [_decide_one(line, allowed_host) for line in lines]
    if any(r is None for r in results):
        return None
    if any(r == "ask" for r in results):
        return "ask"
    return "allow"


def main() -> None:
    allowed_host = sys.argv[1] if len(sys.argv) > 1 else None

    data = json.load(sys.stdin)
    cmd = data.get("tool_input", {}).get("command", "")

    result = decide(cmd, allowed_host)

    if _DEBUG_LOG.exists():
        lines = [line.strip() for line in cmd.split("\n") if line.strip()]
        with open(_DEBUG_LOG, "a") as f:
            if len(lines) > 1:
                f.write(f"cmd={cmd!r}\n")
                for i, line in enumerate(lines):
                    f.write(f"line[{i}]={line!r} -> {_decide_one(line, allowed_host or '')!r}\n")
                f.write(f"decision={result!r}\n---\n")
            else:
                parsed = _parse_ssh(cmd)
                if parsed:
                    host, inner, trailing = parsed
                    f.write(
                        f"cmd={cmd!r}\nhost={host!r}\ninner={inner!r}\n"
                        f"trailing={trailing!r}\ndecision={result!r}\n---\n"
                    )

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
