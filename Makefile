SRC = ssh-readonly.py
TESTS = tests
TOOLS = tools

.PHONY: check lint format test setup install install-hooks pre-commit-hook clean distclean

# Install the hook script to ~/.claude/hooks/
install:
	mkdir -p ~/.claude/hooks
	cp -a $(SRC) ~/.claude/hooks/$(SRC)

# Set up the dev environment (creates/updates venv and installs all dev deps)
setup:
	uv sync --extra dev

# Install git pre-commit hooks (runs setup first)
install-hooks: setup
	uv run pre-commit install

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
	uv run ruff format $(SRC) $(TESTS)

# Test: run test suite. Pass PYTEST_ARGS to forward options/filters to pytest.
#   make test                          — full suite
#   make test PYTEST_ARGS="-k test_debug"     — keyword filter
#   make test PYTEST_ARGS="tests/test_ssh_readonly.py::test_debug_log_written_when_present"
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
