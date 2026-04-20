See README.md for project overview, installation, and development instructions.

This hook is assumed to be installed and active. When a session starts with a
question about SSH commands asking for permission (or not), the first step is
to trace the command through `decide()` — not to explain Claude Code's general
permission system.

To diagnose a specific command:
- Evaluate: `python3 tools/evaluate-command.py <host> '<command>'` — full breakdown of parse + decision
- Fallback (if evaluate-command.py can't be used): `echo '{"tool_input": {"command": "ssh host \"cmd\""}}' | python3 ssh-readonly.py host`
- For live traffic, enable the debug log first: `touch ~/.claude/hooks/ssh-readonly-debug.log` (next to the installed script)

## Development

Prefer `make` targets over invoking tools directly:
- `make check` — lint + full test suite (run before committing)
- `make format` — auto-format source
- `make test` — full test suite
- `make test PYTEST_ARGS="-k test_debug"` — pytest keyword filter
- `make test PYTEST_ARGS="-k 'test_foo or test_bar'"` — compound keyword (inner quotes required)
- `make test PYTEST_ARGS="tests/test_ssh_readonly.py::test_name"` — single test

Invoke pytest directly only when you need options that `make test PYTEST_ARGS=...` doesn't cover (e.g. `-s` to see print output while iterating).

## Privacy

This repo is intended to be shareable as a public project. Do not reference
any personal or environment-specific details in code, comments, commit messages,
or documentation. This includes hostnames, usernames, machine names, file paths
specific to any individual setup, or any other identifying information.

Examples to avoid: real SSH host aliases, local usernames, machine names like
"mycomputer" or "myserver". Use generic placeholders like `dev-server` and
`prod-server` instead.
