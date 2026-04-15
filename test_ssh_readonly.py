#!/usr/bin/env python3
"""Basic smoke tests for ssh-readonly.py.

Run with:  python3 test_ssh_readonly.py
"""
import json
import subprocess
import sys
import unittest

SCRIPT = "ssh-readonly.py"
HOST = "keep"


def run(command: str, host: str = HOST) -> str:
    """Pipe a tool_input JSON to the script and return the permissionDecision."""
    payload = json.dumps({"tool_input": {"command": command}})
    result = subprocess.run(
        [sys.executable, SCRIPT, host],
        input=payload,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"]


class TestApproved(unittest.TestCase):
    def test_grep(self):
        self.assertEqual(run(f'ssh {HOST} "grep foo /etc/passwd"'), "allow")

    def test_cat(self):
        self.assertEqual(run(f'ssh {HOST} "cat /etc/hosts"'), "allow")

    def test_find_safe(self):
        self.assertEqual(run(f'ssh {HOST} "find /var -name \'*.log\'"'), "allow")

    def test_systemctl_status(self):
        self.assertEqual(run(f'ssh {HOST} "systemctl status nginx"'), "allow")

    def test_sudo(self):
        self.assertEqual(run(f'ssh {HOST} "sudo cat /etc/shadow"'), "allow")

    def test_pipeline(self):
        self.assertEqual(run(f'ssh {HOST} "grep error /var/log/syslog | wc -l"'), "allow")

    def test_sed_filter(self):
        self.assertEqual(run(f'ssh {HOST} "grep foo /etc/file | sed \'s/foo/bar/\'"'), "allow")


class TestBlocked(unittest.TestCase):
    def test_wrong_host(self):
        self.assertEqual(run(f'ssh other "grep foo /etc/passwd"'), "ask")

    def test_not_ssh(self):
        self.assertEqual(run('grep foo /etc/passwd'), "ask")

    def test_rm(self):
        self.assertEqual(run(f'ssh {HOST} "rm /tmp/foo"'), "ask")

    def test_systemctl_restart(self):
        self.assertEqual(run(f'ssh {HOST} "systemctl restart nginx"'), "ask")

    def test_redirection(self):
        self.assertEqual(run(f'ssh {HOST} "grep foo /etc/passwd > /tmp/out"'), "ask")

    def test_find_exec(self):
        self.assertEqual(run(f'ssh {HOST} "find /tmp -exec rm {{}} \\;"'), "ask")

    def test_find_delete(self):
        self.assertEqual(run(f'ssh {HOST} "find /tmp -name \'*.tmp\' -delete"'), "ask")

    def test_ip_link_set(self):
        self.assertEqual(run(f'ssh {HOST} "ip link set eth0 down"'), "ask")

    def test_tee_in_pipeline(self):
        self.assertEqual(run(f'ssh {HOST} "grep foo /etc/passwd | tee /tmp/out"'), "ask")

    def test_sed_inplace(self):
        self.assertEqual(run(f'ssh {HOST} "sed -i \'s/foo/bar/\' /etc/file"'), "ask")

    def test_sed_inplace_bak(self):
        self.assertEqual(run(f'ssh {HOST} "sed -i.bak \'s/foo/bar/\' /etc/file"'), "ask")

    def test_sed_inplace_combined_flag(self):
        self.assertEqual(run(f'ssh {HOST} "sed -ni \'s/foo/bar/\' /etc/file"'), "ask")


if __name__ == "__main__":
    unittest.main(verbosity=2)
