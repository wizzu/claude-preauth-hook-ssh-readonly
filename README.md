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

The hook intercepts every `Bash` tool call. For SSH commands targeting the
configured host, it returns one of three decisions:

- **Allow** — inner command matches the read-only allowlist and no unsafe
  patterns are present (output redirection, `sed -i`, `find -exec`, etc.) →
  auto-approved, no prompt
- **Ask** — something looks risky → falls through to Claude Code's permission
  prompt as normal
- **Defer** — not an SSH command, or SSH to a different host → hook does
  nothing, normal Claude Code behavior applies

## Installation

```bash
make install
# equivalent to: cp ssh-readonly.py ~/.claude/hooks/ssh-readonly.py
# (make install preserves the executable bit via cp -a; if copying manually, add chmod +x)
```

## Per-project setup

Run the helper from within the project you want to configure:

```bash
python3 /path/to/claude-preauth-hook-ssh-readonly/tools/add-claude-preauth-hook.py dev-server
```

It shows what it will add, asks for confirmation, and backs up `settings.json`
if one already exists. If the hook for that host is already present, it does
nothing.

To configure manually instead, add a `PreToolUse` hook to `.claude/settings.json`:

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

**First-time setup** (creates `.venv`, installs dev deps, installs git hooks):

```bash
make install-git-commit-hooks
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
make install
# equivalent to: cp ssh-readonly.py ~/.claude/hooks/ssh-readonly.py
```

For ad-hoc checks, see the **Debugging** section above.

## Notes

- The hook must be executable (`chmod +x`)
- Claude Code will ask for one-time approval of a new project-level hook on
  first use — check `/hooks` inside the session if commands aren't being
  auto-approved
- Non-SSH commands and SSH to any host other than the configured one produce no
  hook output, deferring to Claude Code's default permission logic — not
  silently blocked or automatically prompted by the hook

