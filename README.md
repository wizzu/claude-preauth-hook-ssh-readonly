## Installation

Copy (or symlink) the script to `~/.claude/hooks/`:

```bash
cp ssh-readonly.py ~/.claude/hooks/ssh-readonly.py
chmod +x ~/.claude/hooks/ssh-readonly.py
```

## Per-project setup

In each project's `.claude/settings.json`, add a `PreToolUse` hook and pass
the allowed SSH host as an argument:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/ssh-readonly.py <hostname>"
          }
        ]
      }
    ]
  }
}
```

Replace `<hostname>` with the SSH alias used in that project (e.g. `dev-server`
or `prod-server`). Only commands matching that host are auto-approved; SSH to
any other host falls through to the prompt.

## Configuring the allowlist

Two lists at the top of `ssh-readonly.py` control what gets auto-approved.

**`READONLY_COMMANDS`** — patterns matched against the start of the inner
command (after stripping an optional leading `sudo`). Simple commands are plain
strings; commands where only specific subcommands or flags are safe use a regex:

```python
READONLY_COMMANDS = [
    r"cat",
    r"grep",
    ...
    r"systemctl\s+status",
    r"ip\s+(addr|address|link|route|neigh|rule|netns)(\s+(show|list|ls).*)?",
    r"fdisk\s+-l",
]
```

**`UNSAFE_PATTERNS`** — patterns searched across the whole inner command *after*
an allowlist match. If any match, the command falls through to the prompt.
Used to block things that would otherwise slip past a broad allowlist entry:
output redirection, `find -exec`/`-delete`, `sed -i`, `tee` in pipelines, and
`ip` write subcommands (`set`, `add`, `del`, etc.).

## Debugging

The script logs to `~/.claude/hooks/ssh-readonly-debug.log` when that file
exists. To enable:

```bash
touch ~/.claude/hooks/ssh-readonly-debug.log
```

To disable, delete the file. The log records `cmd`, `host`, and `inner` for
each invocation, which is enough to diagnose why a command was or wasn't
auto-approved.

## Development

**First-time setup** (creates `.venv`, installs dev deps, installs git hooks):

```bash
make install-hooks
```

**Common tasks:**

```bash
make check     # all quality checks: lint + test
make lint      # ruff, bandit, mypy, suppression check
make format    # reformat code in place
make test      # run test suite
```

**Editing the allowlist:**

- `READONLY_COMMANDS` and `UNSAFE_PATTERNS` at the top of `ssh-readonly.py` are the
  only things most changes will touch
- Each entry is a Python regex — simple command names are plain strings, but
  entries like `systemctl` and `ip` need subcommand matching to avoid
  accidentally allowing write operations
- The script must stay a single file with no dependencies beyond the standard
  library — it runs in any Python 3 environment without a venv

**Deploying after a change:**

```bash
make check
cp ssh-readonly.py ~/.claude/hooks/ssh-readonly.py
```

For ad-hoc checks, you can also drive the script directly:

```bash
echo '{"tool_input": {"command": "ssh prod-server \"grep foo /etc/conf\""}}' \
  | python3 ssh-readonly.py prod-server
```

Expected output for an approved command:
`{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", ...}}`

## Notes

- The hook must be executable (`chmod +x`)
- Claude Code will ask for one-time approval of a new project-level hook on
  first use — check `/hooks` inside the session if commands aren't being
  auto-approved
- Non-SSH commands and SSH to any host other than the configured one produce no
  hook output, deferring to Claude Code's default permission logic — not
  silently blocked or automatically prompted by the hook

