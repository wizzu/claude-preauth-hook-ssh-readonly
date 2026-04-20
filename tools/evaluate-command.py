#!/usr/bin/env python3
"""Evaluate a shell command string against the ssh-readonly hook and explain the outcome.

Usage:
    # Command as argument
    python3 tools/evaluate-command.py <host> '<command>'

    # Multi-line or complex quoting — read from stdin
    echo 'ssh host "cmd"' | python3 tools/evaluate-command.py <host>

    # Heredoc for multi-line
    python3 tools/evaluate-command.py <host> <<'EOF'
    ssh host "cmd1" && ssh host "cmd2"
    EOF

Exits 0 in all cases (this is a diagnostic tool, not a gate).
"""

import importlib.util
import sys
from pathlib import Path

# --- Load ssh-readonly.py (hyphenated name, not directly importable) ---
_hook_path = Path(__file__).parent.parent / "ssh-readonly.py"
_spec = importlib.util.spec_from_file_location("ssh_readonly", _hook_path)
assert _spec is not None, f"could not load spec from {_hook_path}"
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

_parse_ssh = _mod._parse_ssh
_split_commands = _mod._split_commands
_decide_one = _mod._decide_one
_BENIGN_TRAILING_RE = _mod._BENIGN_TRAILING_RE
_HEREDOC_RE = _mod._HEREDOC_RE
readonly_re = _mod.readonly_re
unsafe_re = _mod.unsafe_re
decide = _mod.decide


# --- Formatting helpers ---

_RESULT_LABELS = {
    "allow": "ALLOW",
    "ask": "ASK  ",
    None: "DEFER",
}

_DECISION_EXPLANATIONS = {
    "allow": "auto-approved (read-only command on configured host)",
    "ask": "blocked — Claude Code will ask for permission",
    None: "falls through to Claude Code's default permissions",
}


def _truncate(s: str, width: int = 80) -> str:
    return s if len(s) <= width else s[: width - 3] + "..."


def _analyze_fragment(fragment: str, allowed_host: str) -> str:
    """Return a multi-line analysis string for a single command fragment."""
    lines = []
    lines.append(f"  {_truncate(fragment)}")

    parsed = _parse_ssh(fragment)
    if not parsed:
        lines.append("    parse:    not recognised as an SSH command")
        lines.append("    result:   DEFER")
        return "\n".join(lines)

    host, inner, trailing = parsed

    host_note = (
        "[match]" if host == allowed_host else f"[no match — allowed host is {allowed_host!r}]"
    )
    lines.append(f"    host:     {host}  {host_note}")
    lines.append(f"    inner:    {inner}")
    lines.append(f"    trailing: {trailing!r}")

    if host != allowed_host:
        lines.append("    result:   DEFER")
        return "\n".join(lines)

    # Trailing check
    if trailing and not _BENIGN_TRAILING_RE.match(trailing):
        lines.append("    trailing: NOT BENIGN — pipe or non-fd/devnull tokens present")
        lines.append("    result:   DEFER")
        return "\n".join(lines)
    elif trailing:
        lines.append("    trailing: benign (fd/devnull redirection only)")
    else:
        lines.append("    trailing: none")

    # Readonly check
    ro_match = readonly_re.match(inner)
    if ro_match:
        lines.append(f"    readonly: MATCH  (matched: {ro_match.group()!r})")
    else:
        lines.append("    readonly: no match")

    # Unsafe check
    unsafe_match = unsafe_re.search(inner)
    if unsafe_match:
        lines.append(f"    unsafe:   MATCH  (matched: {unsafe_match.group()!r})")
    else:
        lines.append("    unsafe:   no match")

    result = _decide_one(fragment, allowed_host)
    lines.append(f"    result:   {_RESULT_LABELS[result]}")
    return "\n".join(lines)


def evaluate(command: str, allowed_host: str) -> None:
    print(f"Host:    {allowed_host}")
    print(f"Command: {_truncate(command)}")
    print()

    fragments = _split_commands(command)

    # Heredoc bail-out (same logic as decide())
    if any(_HEREDOC_RE.search(f) for f in fragments):
        print("Note: heredoc detected — cannot safely classify after splitting")
        print()
        print("Decision: DEFER  (falls through to Claude Code's default permissions)")
        return

    print(f"Fragments: {len(fragments)}")
    for i, fragment in enumerate(fragments, 1):
        print(f"  Fragment {i}:")
        # Re-print with fragment label
        analysis = _analyze_fragment(fragment, allowed_host)
        # Indent the first line (the fragment text) further under the label
        print(analysis)

    print()
    decision = decide(command, allowed_host)
    label = _RESULT_LABELS[decision]
    explanation = _DECISION_EXPLANATIONS[decision]
    print(f"Decision: {label}  ({explanation})")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: evaluate-command.py <host> [command]", file=sys.stderr)
        print("       If command is omitted, it is read from stdin.", file=sys.stderr)
        return 1

    allowed_host = sys.argv[1]

    if len(sys.argv) >= 3:
        command = " ".join(sys.argv[2:])
    else:
        command = sys.stdin.read()

    command = command.strip()
    if not command:
        print("Error: empty command", file=sys.stderr)
        return 1

    evaluate(command, allowed_host)
    return 0


if __name__ == "__main__":
    sys.exit(main())
