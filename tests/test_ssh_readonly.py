#!/usr/bin/env python3
"""Tests for ssh-readonly.py."""

import contextlib
import importlib.util
import io
import json

# B404: needed for the single subprocess integration test (verifies the script as a child process).
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

# Load the script as a module (importlib needed because the filename contains a hyphen)
_script_path = Path(__file__).parent.parent / "ssh-readonly.py"
_spec = importlib.util.spec_from_file_location("ssh_readonly", _script_path)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]
decide = _mod.decide
_parse_ssh = _mod._parse_ssh
_split_commands = _mod._split_commands

HOST = "prod-server"


# ── _parse_ssh ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command,expected",
    [
        # Double-quoted, no trailing
        (f'ssh {HOST} "cat /etc/hosts"', (HOST, "cat /etc/hosts", None)),
        # Double-quoted, benign trailing
        (f'ssh {HOST} "ls /path" 2>/dev/null', (HOST, "ls /path", " 2>/dev/null")),
        # Single-quoted, no trailing
        (f"ssh {HOST} 'cat /etc/hosts'", (HOST, "cat /etc/hosts", None)),
        # Single-quoted, benign trailing
        (f"ssh {HOST} 'ls /path' 2>/dev/null", (HOST, "ls /path", " 2>/dev/null")),
        # Unquoted
        (f"ssh {HOST} cat /etc/hosts", (HOST, "cat /etc/hosts", None)),
        # Single no-arg flag (-t allocates a pseudo-TTY, takes no argument)
        (f'ssh -t {HOST} "cat /etc/hosts"', (HOST, "cat /etc/hosts", None)),
        # Multiple no-arg flags as separate tokens
        (f'ssh -t -q {HOST} "cat /etc/hosts"', (HOST, "cat /etc/hosts", None)),
        # Combined no-arg flags in one token
        (f'ssh -tq {HOST} "cat /etc/hosts"', (HOST, "cat /etc/hosts", None)),
        # With-arg flag: -i consumes the next token (identity file)
        (f'ssh -i /path/to/key {HOST} "cat /etc/hosts"', (HOST, "cat /etc/hosts", None)),
        # Mixed: no-arg flag followed by with-arg flag
        (f'ssh -t -i /path/to/key {HOST} "cat /etc/hosts"', (HOST, "cat /etc/hosts", None)),
        # Mixed: with-arg flag in the middle, no-arg flag after it
        (f'ssh -v -i /path/to/key -q {HOST} "cat /etc/hosts"', (HOST, "cat /etc/hosts", None)),
        # End-of-options marker (--)
        (f'ssh -- {HOST} "cat /etc/hosts"', (HOST, "cat /etc/hosts", None)),
        # Not SSH — returns None
        ("cat /etc/hosts", None),
        ("grep foo /etc/passwd", None),
    ],
)
def test_parse_ssh(command: str, expected: tuple | None) -> None:
    assert _parse_ssh(command) == expected


# ── Approved ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        f'ssh {HOST} "grep foo /etc/passwd"',
        f'ssh {HOST} "cat /etc/hosts"',
        f"ssh {HOST} \"find /var -name '*.log'\"",
        f'ssh {HOST} "systemctl status nginx"',
        f'ssh {HOST} "sudo cat /etc/shadow"',
        f'ssh {HOST} "sudo -i cat /etc/shadow"',
        f'ssh {HOST} "sudo -i ls -la /some/path"',
        f'ssh {HOST} "grep error /var/log/syslog | wc -l"',
        f"ssh {HOST} \"grep foo /etc/file | sed 's/foo/bar/'\"",
        # SSH flags before the host must be skipped, not confused with the hostname
        f'ssh -t {HOST} "cat /etc/hosts"',
        f'ssh -t {HOST} "sudo -i cat /etc/hosts"',
        f"ssh -t {HOST} \"sudo -i cat /etc/hosts 2>/dev/null || echo '(not found)'\"",
        # Benign shell-level fd redirections after the closing quote are ignored
        f'ssh {HOST} "ls /some/path" 2>/dev/null',
        f'ssh {HOST} "cat /etc/hosts" 2>/dev/null',
        f'ssh {HOST} "cat /etc/hosts" 2>&1',
        f'ssh {HOST} "cat /etc/hosts" >/dev/null 2>&1',
    ],
)
def test_approved(command: str) -> None:
    assert decide(command, HOST) == "allow"


# ── Deferred ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command,host",
    [
        (f'ssh {HOST} "grep foo /etc/passwd"', None),  # no host configured
        # Non-benign trailing shell actions — outside the hook's scope; defer rather than deciding
        (f'ssh {HOST} "cat /etc/passwd" > /tmp/out', HOST),
        ('ssh other "grep foo /etc/passwd"', HOST),  # wrong host
        ("grep foo /etc/passwd", HOST),  # not SSH
        ("du -sh /some/local/path", HOST),  # local command
        ("ls -la /tmp", HOST),  # local command
        # Command substitution — can't safely analyse; defer
        (f'ssh {HOST} "cat $(ls /tmp)"', HOST),
        (f'ssh {HOST} "cat `ls /tmp`"', HOST),
    ],
)
def test_deferred(command: str, host: str | None) -> None:
    assert decide(command, host) is None


# ── Blocked ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        f'ssh {HOST} "rm /tmp/foo"',
        f'ssh {HOST} "systemctl restart nginx"',
        f'ssh {HOST} "grep foo /etc/passwd > /tmp/out"',
        f'ssh {HOST} "find /tmp -exec rm {{}} \\;"',
        f"ssh {HOST} \"find /tmp -name '*.tmp' -delete\"",
        f'ssh {HOST} "ip link set eth0 down"',
        f'ssh {HOST} "grep foo /etc/passwd | tee /tmp/out"',
        f"ssh {HOST} \"sed -i 's/foo/bar/' /etc/file\"",
        f"ssh {HOST} \"sed -i.bak 's/foo/bar/' /etc/file\"",
        f"ssh {HOST} \"sed -ni 's/foo/bar/' /etc/file\"",
    ],
)
def test_blocked(command: str) -> None:
    assert decide(command, HOST) == "ask"


# ── Git approved ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        f'ssh {HOST} "git status"',
        f'ssh {HOST} "git log --oneline -5"',
        f'ssh {HOST} "git diff HEAD~1"',
        f'ssh {HOST} "git show HEAD"',
        f'ssh {HOST} "git blame src/main.py"',
        f'ssh {HOST} "git -C /some/path status"',
        f'ssh {HOST} "git -C /some/path log --oneline -5"',
        f'ssh {HOST} "git --no-pager diff"',
        f'ssh {HOST} "git stash list"',
        f'ssh {HOST} "sudo git status"',
        f'ssh {HOST} "sudo -i git -C /some/path status"',
        f'ssh {HOST} "sudo -i git -C /some/path log --oneline -5"',
    ],
)
def test_git_approved(command: str) -> None:
    assert decide(command, HOST) == "allow"


# ── Git blocked ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        f'ssh {HOST} "git commit -m msg"',
        f'ssh {HOST} "git push"',
        f'ssh {HOST} "git pull"',
        f'ssh {HOST} "git checkout main"',
        f'ssh {HOST} "git branch -d old-branch"',
        f'ssh {HOST} "git stash"',
        f'ssh {HOST} "git stash pop"',
        f'ssh {HOST} "git remote add origin url"',
    ],
)
def test_git_blocked(command: str) -> None:
    assert decide(command, HOST) == "ask"


# ── Docker approved ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        f'ssh {HOST} "docker ps"',
        f'ssh {HOST} "docker ps -a"',
        f'ssh {HOST} "docker images"',
        f'ssh {HOST} "docker inspect mycontainer"',
        f'ssh {HOST} "docker logs mycontainer"',
        f'ssh {HOST} "docker stats --no-stream"',
        f'ssh {HOST} "docker top mycontainer"',
        f'ssh {HOST} "docker diff mycontainer"',
        f'ssh {HOST} "docker info"',
        f'ssh {HOST} "docker version"',
        f'ssh {HOST} "docker system df"',
        f'ssh {HOST} "docker network ls"',
        f'ssh {HOST} "docker network inspect mynet"',
        f'ssh {HOST} "docker volume ls"',
        f'ssh {HOST} "docker image ls"',
        f'ssh {HOST} "docker container ls"',
        f'ssh {HOST} "docker container logs mycontainer"',
        f'ssh {HOST} "docker compose ps"',
        f'ssh {HOST} "docker compose logs"',
        f'ssh {HOST} "docker compose config"',
        f'ssh {HOST} "docker-compose ps"',
        f'ssh {HOST} "docker-compose logs myservice"',
        f'ssh {HOST} "sudo docker ps"',
    ],
)
def test_docker_approved(command: str) -> None:
    assert decide(command, HOST) == "allow"


# ── Docker blocked ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        f'ssh {HOST} "docker exec mycontainer sh"',
        f'ssh {HOST} "docker run nginx"',
        f'ssh {HOST} "docker rm mycontainer"',
        f'ssh {HOST} "docker stop mycontainer"',
        f'ssh {HOST} "docker system prune"',
        f'ssh {HOST} "docker network connect mynet mycontainer"',
        f'ssh {HOST} "docker image prune"',
        f'ssh {HOST} "docker-compose up"',
        f'ssh {HOST} "docker compose down"',
    ],
)
def test_docker_blocked(command: str) -> None:
    assert decide(command, HOST) == "ask"


# ── _split_commands ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command, expected",
    [
        # Newline split
        ("cmd1\ncmd2", ["cmd1", "cmd2"]),
        # Blank lines are skipped
        ("cmd1\n\ncmd2", ["cmd1", "cmd2"]),
        # && split
        ("cmd1 && cmd2", ["cmd1", "cmd2"]),
        # || split
        ("cmd1 || cmd2", ["cmd1", "cmd2"]),
        # ; split
        ("cmd1; cmd2", ["cmd1", "cmd2"]),
        # Mixed operators (no newline)
        ("cmd1 && cmd2; cmd3 || cmd4", ["cmd1", "cmd2", "cmd3", "cmd4"]),
        # Mixed operators including newline
        ("cmd1\ncmd2 && cmd3", ["cmd1", "cmd2", "cmd3"]),
        ("cmd1 && cmd2\ncmd3; cmd4", ["cmd1", "cmd2", "cmd3", "cmd4"]),
        # | split
        ("cmd1 | cmd2", ["cmd1", "cmd2"]),
        # Pipe inside double-quoted string — not a split point
        ('ssh host "ls | head"', ['ssh host "ls | head"']),
        # Pipe outside quotes — splits
        ('ssh host "ls" | head', ['ssh host "ls"', "head"]),
        # Operator inside double-quoted string — not a split point
        ('ssh host "cat f || echo x"', ['ssh host "cat f || echo x"']),
        ('ssh host "cmd && other"', ['ssh host "cmd && other"']),
        ('ssh host "a; b"', ['ssh host "a; b"']),
        # Newline inside double-quoted string — not a split point
        ('ssh host "line1\nline2"', ['ssh host "line1\nline2"']),
        # Operator inside single-quoted string — not a split point
        ("ssh host 'grep \"&&\" file'", ["ssh host 'grep \"&&\" file'"]),
        # Mixed: outer && with inner || inside double-quoted arg
        (
            'ssh host "sudo cat /a" && ssh host "sudo git show HEAD 2>/dev/null || echo none"',
            ['ssh host "sudo cat /a"', 'ssh host "sudo git show HEAD 2>/dev/null || echo none"'],
        ),
        # Trailing/leading whitespace is stripped from each fragment
        ("  cmd1  &&  cmd2  ", ["cmd1", "cmd2"]),
        # Single command — no split
        ('ssh host "cat /etc/hosts"', ['ssh host "cat /etc/hosts"']),
        # Empty string
        ("", []),
        # Only whitespace
        ("   ", []),
    ],
)
def test_split_commands(command: str, expected: list[str]) -> None:
    assert _split_commands(command) == expected


# ── Command chaining (newlines, &&, ||, ;) ────────────────────────────────────


@pytest.mark.parametrize(
    "command",
    [
        # Two read-only commands — newline
        f'ssh {HOST} "grep foo /var/log/syslog" 2>&1\nssh {HOST} "ls -lh /var/log/syslog*" 2>&1',
        # Three read-only commands — newline
        f'ssh {HOST} "cat /etc/hosts"\nssh {HOST} "ls /tmp"\nssh {HOST} "ps aux"',
        # Blank lines between commands are ignored
        f'ssh {HOST} "cat /etc/hosts"\n\nssh {HOST} "ls /tmp"',
        # << inside a quoted argument is not a heredoc
        f"ssh {HOST} \"grep '<< marker' /var/log/app.log\"",
        # Real-world case: two sudo read-only commands batched together — newline
        f"ssh {HOST} \"sudo -i grep 'USBCOPYFinished' /var/log/app.log | tail -20\" 2>&1\n"
        f'ssh {HOST} "sudo -i ls -lh /var/log/app.log*" 2>&1',
        # && chaining — both read-only
        f'ssh {HOST} "cat /etc/hosts" && ssh {HOST} "ls /tmp"',
        # Real-world &&: sudo cat then sudo git show, with || fallback inside the quoted arg
        f'ssh {HOST} "sudo -i cat /srv/.gitignore"'
        f' && ssh {HOST} "sudo -i git -C /srv show HEAD:sub/.gitignore 2>/dev/null || echo (none)"',
        # ; chaining — both read-only
        f'ssh {HOST} "cat /etc/hosts"; ssh {HOST} "ls /tmp"',
        # || chaining — both read-only (e.g. fallback on failure)
        f'ssh {HOST} "cat /etc/hosts" || ssh {HOST} "echo unavailable"',
        # Mixed operators (no newline)
        f'ssh {HOST} "cat /etc/hosts" && ssh {HOST} "ls /tmp"; ssh {HOST} "ps aux"',
        # Mixed: newline and && in the same batch
        f'ssh {HOST} "cat /etc/hosts"\nssh {HOST} "ls /tmp" && ssh {HOST} "ps aux"',
        # || inside quoted arg is part of the remote command, not a chain operator
        f'ssh {HOST} "cat /etc/hosts || echo missing"',
        # Inner pipe — both segments read-only
        f'ssh {HOST} "ls /tmp | head -20"',
        f'ssh {HOST} "sudo -i ls /srv | grep conf"',
        # Inner semicolon — both segments read-only
        f'ssh {HOST} "ls /tmp; cat /etc/hosts"',
        # Inner && — both segments read-only
        f'ssh {HOST} "ls /tmp && cat /etc/hosts"',
        # Outer pipe — local segment is read-only
        f'ssh {HOST} "cat /etc/passwd" | grep root',
        f'ssh {HOST} "ls /tmp" | head -20',
        f'ssh {HOST} "cat /etc/hosts" | wc -l',
        # Outer &&, ||, ;, newline — local segment is read-only
        f'ssh {HOST} "cat /etc/passwd" && echo done',
        f'ssh {HOST} "cat /etc/hosts"\nls /tmp',
        f'ssh {HOST} "cat /etc/hosts" && ls /tmp',
        f'ssh {HOST} "cat /etc/hosts" || echo fallback',
        f'ssh {HOST} "cat /etc/hosts"; echo done',
        # Multi-stage outer pipeline — all local segments read-only
        f'ssh {HOST} "cat /etc/passwd" | grep root | wc -l',
    ],
)
def test_chaining_approved(command: str) -> None:
    assert decide(command, HOST) == "allow"


@pytest.mark.parametrize(
    "command",
    [
        # One read-only + one destructive — newline
        f'ssh {HOST} "cat /etc/hosts"\nssh {HOST} "rm /tmp/foo"',
        # Two destructive commands — newline
        f'ssh {HOST} "rm /tmp/foo"\nssh {HOST} "systemctl restart nginx"',
        # One read-only + one destructive — &&
        f'ssh {HOST} "cat /etc/hosts" && ssh {HOST} "rm /tmp/foo"',
        # One read-only + one destructive — ;
        f'ssh {HOST} "cat /etc/hosts"; ssh {HOST} "rm /tmp/foo"',
        # One read-only + one destructive — ||
        f'ssh {HOST} "cat /etc/hosts" || ssh {HOST} "rm /tmp/foo"',
        # Inner pipe — write command after pipe
        f'ssh {HOST} "ls /tmp | rm /tmp/foo"',
        # Inner semicolon — write command after semicolon
        f'ssh {HOST} "ls /tmp; rm /tmp/foo"',
    ],
)
def test_chaining_blocked(command: str) -> None:
    assert decide(command, HOST) == "ask"


@pytest.mark.parametrize(
    "command",
    [
        # One read-only + wrong host
        f'ssh {HOST} "cat /etc/hosts"\nssh other "cat /etc/hosts"',
        # Heredoc (<<WORD at end of line)
        f"ssh {HOST} \"bash -s\" <<'EOF'\ncat /etc/hosts\nEOF",
        f"ssh {HOST} bash <<EOF\ncat /etc/hosts\nEOF",
        # Outer pipe — local segment writes (tee) or has redirection
        f'ssh {HOST} "ls" | tee /tmp/out',
        f'ssh {HOST} "ls" | grep foo > /tmp/out',
        # Outer pipe — local segment is destructive
        f'ssh {HOST} "ls /tmp" | rm /tmp/foo',
        # Outer pipe — command substitution in local segment
        f'ssh {HOST} "ls" | head $(cat /etc/passwd)',
    ],
)
def test_chaining_deferred(command: str) -> None:
    assert decide(command, HOST) is None


# ── Debug log ─────────────────────────────────────────────────────────────────


def test_debug_log_path_is_next_to_script() -> None:
    """_DEBUG_LOG must resolve to the same directory as the script itself."""
    assert _mod._DEBUG_LOG == _script_path.parent / "ssh-readonly-debug.log"


def _run_main(monkeypatch: pytest.MonkeyPatch, cmd: str, log_path: Path) -> None:
    """Call main() with a controlled _DEBUG_LOG, stdin, and argv; swallow sys.exit."""
    payload = json.dumps({"tool_input": {"command": cmd}})
    monkeypatch.setattr(_mod, "_DEBUG_LOG", log_path)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(payload.encode())))
    monkeypatch.setattr("sys.argv", ["ssh-readonly.py", HOST])
    with contextlib.suppress(SystemExit):
        _mod.main()


def test_debug_log_not_written_when_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No log file is created when the sentinel file does not exist."""
    log_path = tmp_path / "ssh-readonly-debug.log"
    _run_main(monkeypatch, f'ssh {HOST} "cat /etc/hosts"', log_path)
    assert not log_path.exists()


def test_debug_log_written_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When the sentinel file exists, each invocation appends a structured entry."""
    log_path = tmp_path / "ssh-readonly-debug.log"
    log_path.touch()

    cmd = f'ssh {HOST} "cat /etc/hosts"'
    _run_main(monkeypatch, cmd, log_path)

    content = log_path.read_text()
    assert f"cmd={cmd!r}" in content
    assert f"host={HOST!r}" in content
    assert "inner='cat /etc/hosts'" in content
    assert "decision='allow'" in content
    assert content.endswith("---\n")


def test_debug_log_multiline_lists_per_line_decisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Multi-line commands log each constituent line and its decision, plus the aggregate."""
    log_path = tmp_path / "ssh-readonly-debug.log"
    log_path.touch()

    line0 = f'ssh {HOST} "cat /etc/hosts"'
    line1 = f'ssh {HOST} "ls /tmp"'
    cmd = f"{line0}\n{line1}"
    _run_main(monkeypatch, cmd, log_path)

    content = log_path.read_text()
    assert f"cmd={cmd!r}" in content
    assert f"line[0]={line0!r} -> 'allow'" in content
    assert f"line[1]={line1!r} -> 'allow'" in content
    assert "decision='allow'" in content
    assert content.endswith("---\n")


# ── Integration ───────────────────────────────────────────────────────────────


def test_script_subprocess() -> None:
    """Verify the script works correctly as a child process (covers argv/stdin/stdout)."""
    payload = json.dumps({"tool_input": {"command": f'ssh {HOST} "cat /etc/hosts"'}})
    # B603: args are fully controlled — sys.executable, a trusted local script path, string literal.
    result = subprocess.run(  # nosec B603
        [sys.executable, str(_script_path), HOST],
        input=payload,
        capture_output=True,
        text=True,
    )
    decision = json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"]
    assert decision == "allow"
