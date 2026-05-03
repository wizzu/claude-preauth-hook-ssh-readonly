#!/usr/bin/env python3
"""Add a claude-preauth-hook (ssh-readonly) entry to a project's .claude/settings.json.

Run from within the project you want to configure, or pass --dir explicitly.

Usage:
    python3 tools/add-claude-preauth-hook.py <hostname>
    python3 tools/add-claude-preauth-hook.py <hostname> --dir /path/to/project
"""

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

HOOK_COMMAND = "~/.claude/hooks/ssh-readonly.py {host}"


def _hook_exists(settings: dict[str, Any], command: str) -> bool:
    for block in settings.get("hooks", {}).get("PreToolUse", []):
        for hook in block.get("hooks", []):
            if hook.get("command") == command:
                return True
    return False


def _backup_path(settings_path: Path) -> Path:
    candidate = settings_path.with_suffix(".json.bak")
    n = 2
    while candidate.exists():
        candidate = settings_path.with_name(f"{settings_path.stem}.json.bak.{n}")
        n += 1
    return candidate


def _inject(settings: dict[str, Any], command: str) -> None:
    hooks: dict[str, Any] = settings.setdefault("hooks", {})
    pre_tool_use: list[Any] = hooks.setdefault("PreToolUse", [])

    bash_block = next((b for b in pre_tool_use if b.get("matcher") == "Bash"), None)
    if bash_block is None:
        bash_block = {"matcher": "Bash", "hooks": []}
        pre_tool_use.append(bash_block)

    bash_block.setdefault("hooks", []).append({"type": "command", "command": command})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="SSH hostname or alias to configure")
    parser.add_argument(
        "--dir",
        required=True,
        metavar="DIR",
        help="directory containing .claude/ — use a project path or ~ for global config",
    )
    args = parser.parse_args()

    settings_path = Path(args.dir).resolve() / ".claude" / "settings.json"
    command = HOOK_COMMAND.format(host=args.host)

    settings: dict[str, Any] = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except json.JSONDecodeError as e:
            print(f"Error: {settings_path} is not valid JSON: {e}", file=sys.stderr)
            return 1

    if _hook_exists(settings, command):
        print(f"Hook for '{args.host}' is already configured in {settings_path}.")
        return 0

    print(f"Will add to {settings_path}:")
    print(f'  PreToolUse / Bash: "{command}"')
    if not settings_path.exists():
        print("  (file will be created)")

    answer = input("Proceed? [y/N] ").strip().lower()
    if answer != "y":
        print("Aborted.")
        return 0

    if settings_path.exists():
        backup = _backup_path(settings_path)
        shutil.copy2(settings_path, backup)
        print(f"Backup: {backup}")

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    _inject(settings, command)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    print(f"Done. Hook for '{args.host}' added.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
