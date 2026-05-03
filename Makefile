SRC = ssh-readonly.py
TESTS = tests
TOOLS = tools

.PHONY: all check lint format test setup install install-git-commit-hooks add-claude-preauth-hook pre-commit-hook clean distclean

# Default: run all checks (no system modifications)
all: check

# Install the hook script to ~/.claude/hooks/
install:
	mkdir -p ~/.claude/hooks
	cp -a $(SRC) ~/.claude/hooks/$(SRC)

# Set up the dev environment (creates/updates venv and installs all dev deps)
setup:
	uv sync --extra dev

# Install git pre-commit hooks for this repo (runs setup first)
install-git-commit-hooks: setup
	uv run pre-commit install

# Add a PreToolUse hook for the given SSH host to .claude/settings.json.
# Use DIR=~ for global config or DIR=/path/to/project for per-project config.
# Usage: make add-claude-preauth-hook SSHHOST=<hostname> DIR=<path|~>
add-claude-preauth-hook:
	@[ -n "$(SSHHOST)" ] || { echo "Usage: make add-claude-preauth-hook SSHHOST=<hostname> DIR=<path|~>"; exit 1; }
	@[ -n "$(DIR)" ] || { echo "Usage: make add-claude-preauth-hook SSHHOST=<hostname> DIR=<path|~>"; exit 1; }
	python3 $(TOOLS)/add-claude-preauth-hook.py --dir $(DIR) $(SSHHOST)

# Run all checks (lint + test). Does not auto-format.
check: lint test

# Lint: static analysis, type checking, security scan, format check
lint:
	@echo "==> lint"
	uv run --extra dev ruff format --check $(SRC) $(TESTS) $(TOOLS)
	uv run --extra dev ruff check $(SRC) $(TESTS) $(TOOLS)
	uv run --extra dev bandit -r $(SRC) $(TESTS) $(TOOLS) -c pyproject.toml -q
	uv run --extra dev mypy $(SRC) $(TOOLS)
	python3 $(TOOLS)/check-suppressions.py $(SRC) $(TESTS)

# Entry point for the git pre-commit hook (see .pre-commit-config.yaml at repo root)
pre-commit-hook: lint

# Format: auto-reformat source code in place
format:
	@echo "==> format"
	uv run ruff format $(SRC) $(TESTS) $(TOOLS)

# Test: run test suite. Pass PYTEST_ARGS to forward options/filters to pytest.
#   make test                                           — full suite
#   make test PYTEST_ARGS="-k test_debug"              — keyword filter (single word)
#   make test PYTEST_ARGS="-k 'test_foo or test_bar'"  — compound keyword (inner quotes required)
#   make test PYTEST_ARGS="tests/test_ssh_readonly.py::test_name"  — single test
test:
	@echo "==> test"
	uv run --extra dev pytest $(TESTS) $(PYTEST_ARGS)

# Remove caches and coverage artifacts
clean:
	@echo "==> clean"
	rm -rf .coverage .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

# Remove everything including the venv (requires 'make setup' to rebuild)
distclean: clean
	@echo "==> distclean"
	rm -rf .venv
