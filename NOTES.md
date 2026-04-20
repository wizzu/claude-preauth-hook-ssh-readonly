# Notes

## Expanding scope: a collection of domain-focused hooks

The project scope could grow from a single SSH hook into a small collection of
hooks, each responsible for one domain of commands. Claude Code runs all matching
hooks in parallel and takes the most restrictive decision, so the hooks compose
cleanly without coupling.

### Design principle

Each hook owns one domain and does nothing outside it — if a command isn't
recognisably in-scope, the hook defers (exits 0 with no output). This keeps
individual hooks small and reviewable, avoids a single monolithic classifier, and
makes it easy to add or remove a hook without touching the others.

### Planned hooks

| Hook | Domain |
|------|--------|
| `ssh-readonly.py` | SSH commands to a configured remote host (exists) |
| `git-readonly.py` | Local git read operations (`log`, `status`, `diff`, `show`, …) |
| `local-readonly.py` | Other local read-only commands (`cat`, `grep`, `docker ps`, …) |

Splitting git into its own hook makes sense because git subcommand classification
is already non-trivial (see the existing SSH hook's git patterns), and there are
enough edge cases (branch/tag/remote have both read and write forms) to warrant
focused attention. If other domains turn out to be similarly complex (e.g. `gh`
CLI, `docker`) they could get their own hooks too.

### Configuration (example)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "python3 /path/to/ssh-readonly.py myhost" },
          { "type": "command", "command": "python3 /path/to/git-readonly.py" },
          { "type": "command", "command": "python3 /path/to/local-readonly.py" }
        ]
      }
    ]
  }
}
```

### Shared infrastructure

`_split_commands()` (quote-aware split on `&&`, `||`, `;`, newlines) and the
`UNSAFE_PATTERNS` blocklist (output redirection, `find -exec`, `sed -i`, …) are
useful in every hook. The right approach is an open question:

- **Duplicate** — each script is fully self-contained; simple to install and
  review, but changes to shared logic must be applied in multiple places.
- **Shared `lib.py`** — single source of truth, but each installed hook now has
  a runtime dependency on a file in a specific location.
- **Build step** — hooks are authored with imports from `lib.py` and a script
  inlines the shared code before install, producing standalone files. Adds
  tooling complexity but keeps both authoring and deployment clean.

The standalone-file property is worth preserving if possible — it makes
installation trivial and removes any "where is lib.py relative to the hook?"
question at runtime.

### Open questions

- `gh` CLI: read subcommands (`gh pr list`, `gh issue view`) are safe; write ones
  (`gh pr merge`, `gh pr comment`) are not. Complex enough to warrant its own hook,
  or does it fit in `local-readonly.py` with a multi-word pattern table?
- `curl`: a plain `curl <url>` is a GET (read-only); `-X POST`, `--data`, `-o`
  etc. make it a write. Probably belongs in `local-readonly.py` with explicit flag
  checks.
- `docker`: read subcommands (`ps`, `logs`, `inspect`, …) vs write ones (`run`,
  `rm`, `exec`, …). Already handled in the SSH hook's pattern list — reuse that
  in `local-readonly.py`.

### Cross-domain pipelines

The "each hook owns one domain" principle breaks down for pipelines that mix
domains, such as:

```
ssh host "sudo -i cat /path/to/file" 2>/dev/null | grep -A 20 "pattern"
```

This is clearly read-only, but no single hook can approve it:

- **ssh hook**: parses the command, finds `trailing = "2>/dev/null | grep ..."`,
  which fails `_BENIGN_TRAILING_RE` (only pure fd/devnull redirections pass).
  Returns `None` — defer.
- **local hook** (hypothetical): sees the full command; the first token is `ssh`,
  not a local read command. Returns `None` — defer.

Two defers means the overall decision is defer — Claude Code asks for permission
despite the command being entirely read-only.

**Why splitting on `|` doesn't fix this on its own**

If `_split_commands()` were extended to split on `|`, the two segments would be:
- `ssh host "..." 2>/dev/null` → ssh hook: allow; local hook: defer (not local)
- `grep -A 20 "pattern"` → local hook: allow; ssh hook: defer (not SSH)

Each hook still encounters one out-of-domain segment and returns overall `None`.
The hooks have no way to cooperate — they run in parallel, each sees the whole
command, and "most restrictive wins" means two partial defers still equal defer.

**Viable paths**

1. **Extend the ssh hook's trailing classification.** A pipe into a local
   read-only command doesn't make the SSH command write-capable; it only
   transforms the output locally. The ssh hook already owns trailing
   classification — extend it to recognise `| <safe-local-cmd>` in addition to
   pure fd/devnull redirections. Requires a local-safe-command allowlist that
   excludes dangerous cases (`tee`, `xargs`, `sudo`, etc.). Contained change, no
   new infrastructure needed, but it conflates two domains inside one hook.

2. **Split on `|` and add segment-ownership semantics.** A hook that defers
   because a segment is out-of-domain is different from one that defers because
   the segment is unsafe. If hooks could signal "I don't own this segment" vs "I
   own this segment and it's risky", an aggregation layer could combine partial
   approvals across hooks. This doesn't fit the current hook protocol and would
   require a new coordination mechanism.

3. **A pipeline coordinator hook.** A dedicated hook that handles mixed-domain
   pipelines: splits on `|`, classifies each segment against all domain rules
   (from a shared library), and emits a single decision for the whole pipeline.
   Conceptually cleanest, but depends on the shared-infrastructure question being
   resolved first.

Path 1 is the most practical near-term fix given the current single-hook
architecture. Paths 2 and 3 make more sense once multiple hooks exist and the
shared-infrastructure approach is settled.

### Reference

`https://github.com/DavidTeju/shared-skills/blob/main/hooks/user-level/readonly-gate.sh`
is a comprehensive Perl implementation covering local commands (git, docker, gh,
curl, npm, brew, etc.) with two-phase classification (whole-command write scan,
then per-segment analysis). Good source of ideas for command lists and
unsafe-flag patterns; more thorough than what we'd start with, but useful
reference material.
