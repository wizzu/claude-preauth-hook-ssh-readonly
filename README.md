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

Replace `<hostname>` with the SSH alias used in that project (e.g. `keep` or
`tower`). Only commands matching that host are auto-approved; SSH to any other
host falls through to the prompt.

## Configuring the allowlist

The read-only command patterns are defined at the top of `ssh-readonly.py` in
the `READONLY_COMMANDS` list. Each entry is a Python regex matched against the
inner command (after stripping an optional leading `sudo`).

Simple commands are just plain strings:

```python
READONLY_COMMANDS = [
    r"cat",
    r"grep",
    ...
]
```

Commands where only specific subcommands/flags are safe use a regex:

```python
r"systemctl\s+status",
r"ip\s+(addr|address|link|route|neigh|rule|netns)(\s+(show|list|ls).*)?",
r"fdisk\s+-l",
```

## Debugging

Add this block right after `inner` is parsed to log what the script sees:

```python
import os
with open(os.path.expanduser("~/.claude/hooks/debug.log"), "a") as f:
    f.write(f"cmd={cmd!r}\nhost={host!r}\ninner={inner!r}\n---\n")
```

Remove it when done.

## Notes

- The hook must be executable (`chmod +x`)
- Claude Code will ask for one-time approval of a new project-level hook on
  first use — check `/hooks` inside the session if commands aren't being
  auto-approved
- Cross-host SSH (e.g. `ssh keep` from the tower project) hits the host check
  and falls through to the normal prompt — not silently blocked

