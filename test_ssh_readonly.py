#!/usr/bin/env python3
"""Basic smoke tests for ssh-readonly.py.

Run with:  python3 test_ssh_readonly.py
"""
import json
import subprocess
import sys
import unittest

SCRIPT = "ssh-readonly.py"
HOST = "prod-server"


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


class TestDockerApproved(unittest.TestCase):
    def test_docker_ps(self):
        self.assertEqual(run(f'ssh {HOST} "docker ps"'), "allow")

    def test_docker_ps_all(self):
        self.assertEqual(run(f'ssh {HOST} "docker ps -a"'), "allow")

    def test_docker_images(self):
        self.assertEqual(run(f'ssh {HOST} "docker images"'), "allow")

    def test_docker_inspect(self):
        self.assertEqual(run(f'ssh {HOST} "docker inspect mycontainer"'), "allow")

    def test_docker_logs(self):
        self.assertEqual(run(f'ssh {HOST} "docker logs mycontainer"'), "allow")

    def test_docker_stats(self):
        self.assertEqual(run(f'ssh {HOST} "docker stats --no-stream"'), "allow")

    def test_docker_top(self):
        self.assertEqual(run(f'ssh {HOST} "docker top mycontainer"'), "allow")

    def test_docker_diff(self):
        self.assertEqual(run(f'ssh {HOST} "docker diff mycontainer"'), "allow")

    def test_docker_info(self):
        self.assertEqual(run(f'ssh {HOST} "docker info"'), "allow")

    def test_docker_version(self):
        self.assertEqual(run(f'ssh {HOST} "docker version"'), "allow")

    def test_docker_system_df(self):
        self.assertEqual(run(f'ssh {HOST} "docker system df"'), "allow")

    def test_docker_network_ls(self):
        self.assertEqual(run(f'ssh {HOST} "docker network ls"'), "allow")

    def test_docker_network_inspect(self):
        self.assertEqual(run(f'ssh {HOST} "docker network inspect mynet"'), "allow")

    def test_docker_volume_ls(self):
        self.assertEqual(run(f'ssh {HOST} "docker volume ls"'), "allow")

    def test_docker_image_ls(self):
        self.assertEqual(run(f'ssh {HOST} "docker image ls"'), "allow")

    def test_docker_container_ls(self):
        self.assertEqual(run(f'ssh {HOST} "docker container ls"'), "allow")

    def test_docker_container_logs(self):
        self.assertEqual(run(f'ssh {HOST} "docker container logs mycontainer"'), "allow")

    def test_docker_compose_ps(self):
        self.assertEqual(run(f'ssh {HOST} "docker compose ps"'), "allow")

    def test_docker_compose_logs(self):
        self.assertEqual(run(f'ssh {HOST} "docker compose logs"'), "allow")

    def test_docker_compose_config(self):
        self.assertEqual(run(f'ssh {HOST} "docker compose config"'), "allow")

    def test_docker_hyphen_compose_ps(self):
        self.assertEqual(run(f'ssh {HOST} "docker-compose ps"'), "allow")

    def test_docker_hyphen_compose_logs(self):
        self.assertEqual(run(f'ssh {HOST} "docker-compose logs myservice"'), "allow")

    def test_sudo_docker_ps(self):
        self.assertEqual(run(f'ssh {HOST} "sudo docker ps"'), "allow")


class TestDockerBlocked(unittest.TestCase):
    def test_docker_exec(self):
        self.assertEqual(run(f'ssh {HOST} "docker exec mycontainer sh"'), "ask")

    def test_docker_run(self):
        self.assertEqual(run(f'ssh {HOST} "docker run nginx"'), "ask")

    def test_docker_rm(self):
        self.assertEqual(run(f'ssh {HOST} "docker rm mycontainer"'), "ask")

    def test_docker_stop(self):
        self.assertEqual(run(f'ssh {HOST} "docker stop mycontainer"'), "ask")

    def test_docker_system_prune(self):
        self.assertEqual(run(f'ssh {HOST} "docker system prune"'), "ask")

    def test_docker_network_connect(self):
        self.assertEqual(run(f'ssh {HOST} "docker network connect mynet mycontainer"'), "ask")

    def test_docker_image_prune(self):
        self.assertEqual(run(f'ssh {HOST} "docker image prune"'), "ask")

    def test_docker_hyphen_compose_up(self):
        self.assertEqual(run(f'ssh {HOST} "docker-compose up"'), "ask")

    def test_docker_compose_down(self):
        self.assertEqual(run(f'ssh {HOST} "docker compose down"'), "ask")


if __name__ == "__main__":
    unittest.main(verbosity=2)
