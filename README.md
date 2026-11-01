# safety-guard

A shared command/path safety guard for LLM-driven execution paths.

When an autonomous agent (a self-resume worker, an MCP bridge, a scenario
runner) is allowed to run shell commands or write files, every execution path
needs the SAME denylist — a pattern added in one place should protect all of
them. `safety_guard` is that single source of truth.

## What it does

Two checks, both pure functions, both stdlib-only:

- `check_command(command) -> str | None` — a shell command line. Returns the
  matched deny pattern, or `None` if the command is safe.
- `check_path_write(path, root) -> str | None` — a file-write path. Returns a
  denial reason, or `None` if the path stays inside the workspace root.

Deny categories:

| Category | Examples |
|---|---|
| destructive | `sudo`, `dd`, `mkfs`, `shutdown`, `reboot`, fork bombs, recursive `rm` |
| repo-destruction | `git clean -f`, `git reset --hard`, `git push --delete/--mirror`, branch deletion |
| exfiltration | `curl`/`wget` POST, `scp`/`rsync` out, `nc`, base64-piped uploads |
| persistence | `crontab`, `launchctl`, `ssh-keygen`/`ssh-copy-id`, keychain writes |

## Design notes

- **A denylist is a floor, not a ceiling.** It raises the cost of an injected
  or hallucinated destructive action; it does not make one impossible. Pair it
  with independent second signals (a mass-deletion gate, server-side
  hardening) so no single layer is the only defense.
- **The denylist is data, not code.** `DENY_PATTERNS` is a plain list of
  regexes at the top of the module. Adding a pattern is a one-line change that
  every consumer inherits.
- **Stdlib-only on purpose.** It must import cheaply from any execution path,
  including ones that deliberately keep their imports minimal.

## Quickstart

```python
from pathlib import Path
from safety_guard import check_command, check_path_write

root = Path("/path/to/workspace")

check_command("rm -rf /")               # -> the matched deny pattern (denied)
check_command("ls -la")                 # -> None (safe)
check_path_write("/etc/passwd", root)   # -> "absolute path not allowed: ..." (denied)
check_path_write("../outside.py", root) # -> "path traversal not allowed: ..." (denied)
check_path_write("src/main.py", root)   # -> None (safe)
```

## Tests

```sh
python -m pytest tests/ -q
```

The tests pin the denylist: a destructive command must be denied, a benign one
must pass, and the path guard must keep writes inside the workspace.

## License

MIT — see [LICENSE](LICENSE).

---

Built and maintained by [Thanmai Labs](https://thanmailabs.com) — a local-first AI studio. [Watch how we build](https://www.youtube.com/@thanmailabs).
