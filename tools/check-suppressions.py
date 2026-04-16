#!/usr/bin/env python3
"""Check that nosec/noqa suppression annotations have an explanatory comment on the preceding line.

Rules:
- Every suppression annotation (# nosec, # noqa) must have a non-empty comment
  on the immediately preceding line (or as part of a contiguous comment block above it).
- If the annotation specifies a rule ID (e.g. # nosec B404, # noqa: C901), that ID
  must appear somewhere in the preceding comment block.

Usage: python3 tools/check-suppressions.py [path ...]
Defaults to src/ and tests/ if no paths are given.
Exits 0 if all suppressions are compliant, 1 if any violations are found.
"""

import re
import sys
from pathlib import Path

# Matches # nosec or # noqa as suppression annotations (not as prose)
SUPPRESSION_RE = re.compile(r"#\s*(nosec|noqa)\b")

# Matches any comment line (used to identify comment blocks)
COMMENT_LINE_RE = re.compile(r"^\s*#")

# Matches a non-empty comment: # followed by at least one non-whitespace character
NONEMPTY_COMMENT_RE = re.compile(r"^\s*#\s*\S")


def extract_rule_ids(line: str) -> list[str]:
    """Extract rule identifiers from a nosec/noqa annotation."""
    m = re.search(r"#\s*nosec\s+([\w\s]+)", line)
    if m:
        return m.group(1).split()
    m = re.search(r"#\s*noqa:\s*([\w,\s]+)", line)
    if m:
        return [r.strip() for r in m.group(1).split(",") if r.strip()]
    return []


def preceding_comment_block(lines: list[str], i: int) -> list[str]:
    """Return the unbroken run of comment lines immediately above line i (nearest first)."""
    block = []
    j = i - 1
    while j >= 0 and COMMENT_LINE_RE.match(lines[j]):
        block.append(lines[j])
        j -= 1
    return block


def check_file(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    violations = []
    for i, line in enumerate(lines):
        if not SUPPRESSION_RE.search(line):
            continue

        block = preceding_comment_block(lines, i)

        if not block or not NONEMPTY_COMMENT_RE.match(block[0]):
            violations.append(
                f"{path}:{i + 1}: suppression annotation requires an explanatory"
                f" comment on the preceding line"
            )
            continue

        rule_ids = extract_rule_ids(line)
        if rule_ids:
            block_text = " ".join(block)
            missing = [rid for rid in rule_ids if rid not in block_text]
            if missing:
                violations.append(
                    f"{path}:{i + 1}: suppression comment block must mention"
                    f" rule ID(s): {', '.join(missing)}"
                )

    return violations


def main() -> int:
    roots = [Path(a) for a in sys.argv[1:]] or [Path("src"), Path("tests")]
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(sorted(root.rglob("*.py")))

    violations: list[str] = []
    for path in files:
        violations.extend(check_file(path))

    for v in violations:
        print(v)

    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
