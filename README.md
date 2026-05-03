# claude-preauth-hook-ssh-readonly

A [Claude Code](https://claude.ai/code) `PreToolUse` hook that auto-approves
safe, read-only SSH commands and lets everything else fall through to Claude
Code's normal permission prompt.

## When to use this

If you work with Claude in a context where it issues SSH commands — e.g.
inspecting a remote server, reading logs, or checking config — Claude will ask
permission before every command. Most are harmless reads (`cat`, `grep`, `ls`,
`systemctl status`), but some could modify state.

This hook splits that burden: it silently approves commands that match a
read-only allowlist and does nothing for everything else, so Claude Code's
built-in prompt still handles writes and anything ambiguous.

## How it works

Claude Code's `PreToolUse` hook interface supports three standard outcomes for
any tool call: auto-approve it, force a permission prompt, or defer to Claude
Code's default behavior. This script classifies each SSH command into one of
those outcomes:

- **Allow** — inner command matches the read-only allowlist and no unsafe
  patterns are present (output redirection, `sed -i`, `find -exec`, etc.) →
  auto-approved, no prompt
- **Ask** — inner command could modify state → forces Claude Code's permission prompt
- **Defer** — not an SSH command, or SSH to a different host → hook produces
  no output, normal Claude Code behavior applies

## Getting started

**Install the hook script** (once per machine):

```bash
make check     # optional but recommended: verify tests pass before installing
make install   # copy the hook script to ~/.claude/hooks/
```

**Configure where you want the hook active.** It can be added per-project
(only takes effect in that project) or globally (takes effect in all sessions):

```bash
# Per-project — only active within that project:
make add-claude-preauth-hook SSHHOST=<hostname> DIR=/path/to/project

# Global — active in all Claude Code sessions:
make add-claude-preauth-hook SSHHOST=<hostname> DIR=~
```

The command shows what it will add, asks for confirmation, and backs up
`settings.json` if one already exists. If the hook for that host is already
present, it does nothing.

To configure manually instead, add a `PreToolUse` hook to
`.claude/settings.json` (in the project directory or in `~/.claude/`):

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

Replace `<hostname>` with the SSH alias to approve. Only commands matching that
host are auto-approved; SSH to any other host falls through to the prompt.

> **Note:** Claude Code will ask for one-time approval of a newly configured
> hook on first use. If commands aren't being auto-approved as expected, run
> `/hooks` inside the session to check the hook's status.

## Configuring the allowlist

Two lists at the top of `ssh-readonly.py` control what gets auto-approved.

**`READONLY_COMMANDS`** — patterns matched against the start of the inner
command (after stripping an optional leading `sudo`, including flags like
`sudo -i`). Simple commands are plain strings; commands where only specific
subcommands or flags are safe use a regex:

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

**Evaluating a specific command** — to understand how the hook classifies a
given command string (post-fact analysis, development), use
`tools/evaluate-command.py`:

```bash
python3 tools/evaluate-command.py <host> '<command>'

# Multi-line or complex quoting: read from stdin
echo 'ssh host "cmd"' | python3 tools/evaluate-command.py <host>
```

It prints a full breakdown: how the command was split into fragments, the
parsed host/inner/trailing for each, which regex matched (or didn't), and the
final decision (`ALLOW` / `ASK` / `DEFER`).

If you need direct control over the raw hook input (e.g. to test edge cases in
the JSON parsing), you can drive the script directly:

```bash
echo '{"tool_input": {"command": "ssh prod-server \"grep foo /etc/conf\""}}' \
  | python3 ssh-readonly.py prod-server
```

**Debugging a live session** — the script logs to `ssh-readonly-debug.log` in
the same directory as the installed script when that file exists. To enable:

```bash
touch ~/.claude/hooks/ssh-readonly-debug.log
```

To disable, delete the file. The log records `cmd`, `host`, `inner`,
`trailing`, and `decision` for each invocation.

## Development

**Set up the dev environment** (once):

```bash
make install-git-commit-hooks   # create venv, install deps, install pre-commit hooks
make install                    # also run this if you want to use the hook yourself
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
make install
```

For ad-hoc checks, see the **Debugging** section above.

## Make targets

| Target | Description |
|---|---|
| `make` / `make check` | Run all checks: lint + tests |
| `make lint` | Static analysis, type checking, format check |
| `make format` | Auto-reformat source code |
| `make test` | Run test suite |
| `make install` | Copy hook script to `~/.claude/hooks/` |
| `make add-claude-preauth-hook SSHHOST=<hostname> DIR=<path\|~>` | Add hook to `.claude/settings.json` (project path or `~` for global) |
| `make install-git-commit-hooks` | Set up dev environment (venv + pre-commit) |
| `make clean` | Remove caches and artifacts |
| `make distclean` | Remove everything including venv |

## Notes

- The hook must be executable (`chmod +x`) — `make install` handles this; if
  copying manually, run `chmod +x ~/.claude/hooks/ssh-readonly.py`
- Non-SSH commands and SSH to any host other than the configured one produce no
  hook output — they are not silently blocked, just unaffected by this hook
