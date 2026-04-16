#!/usr/bin/env python3
"""Tests for ssh-readonly.py."""

import importlib.util
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

HOST = "prod-server"


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
    ],
)
def test_approved(command: str) -> None:
    assert decide(command, HOST) == "allow"


# ── Deferred ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "command,host",
    [
        (f'ssh {HOST} "grep foo /etc/passwd"', None),  # no host configured
        ('ssh other "grep foo /etc/passwd"', HOST),  # wrong host
        ("grep foo /etc/passwd", HOST),  # not SSH
        ("du -sh /some/local/path", HOST),  # local command
        ("ls -la /tmp", HOST),  # local command
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
