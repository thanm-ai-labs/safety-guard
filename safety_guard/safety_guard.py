"""Shared command/path safety guard for LLM-driven execution paths.

This is the single source of truth for the denylist that gates any command a
model is allowed to run through an agent tool (the autonomous worker, the
DevTools MCP bridge). It exists so every execution path enforces the SAME
policy — a pattern added here protects all of them at once.

Two classes of guard:
  * check_command  — a shell command line. Returns the matched deny pattern
                     (or None if safe).
  * check_path_write — a file-write path. Returns a denial reason (or None if
                     the path stays inside the workspace root).

A denylist is a floor, not a ceiling: it raises the cost of an injected or
hallucinated destructive action, it does not make one impossible. The
mass-deletion gate (git_safety.py) and the server-side hardening
(harden_bare_repo.sh) are the independent second signals.

Categories (prompt-injection hardening; repo-destruction):
  destructive      — damage the host or the repo
  repo-destruction — irreversibly delete repo state (the repo-destruction additions)
  exfiltration     — move data off the machine (the worker has no legitimate
                     network egress: LLM calls go through llm_client, not shell)
  persistence      — survive the session (cron/launchd/ssh keys/keychain)
"""

from __future__ import annotations

import re
from pathlib import Path

# Commands that must never be executed by an autonomous / LLM-driven path.
DENY_PATTERNS: list[str] = [
    # --- destructive (host) ---
    r"\bsudo\b",
    r"\bdd\b",
    r"\bmkfs",
    r"\bshutdown\b",
    r"\breboot\b",
    r":\(\)\s*\{.*\}\s*;",  # fork bomb
    r">\s*/dev/sd",
    # --- repo destruction ---
    # Any recursive rm, any target. An autonomous path must not recursively
    # delete — a build-dir cleanup is decomposed, not `rm -rf`'d. (Subsumes the
    # old `rm -rf /` rule; kept broad on purpose.)
    r"\brm\s+-[a-zA-Z]*[rR]",
    r"\bgit\s+clean\s+-[a-zA-Z]*f",  # git clean -f / -fd / -fdx (not -n dry run)
    r"\bgit\s+reset\s+--hard\b",
    r"\bfind\b[^|;&]*\s-delete\b",  # find ... -delete
    r"\bgit\s+push\s+--force\b",
    r"\bgit\s+push\s+--delete\b",  # delete a remote ref
    r"\bgit\s+push\s+--mirror\b",  # overwrite the whole remote
    r"\bgit\s+remote\s+(set-url|remove|rm)\b",  # re-point / drop a remote
    r"\bgit\s+gc\s+--prune=now\b",  # irreversible object deletion
    # --- exfiltration: network egress ---
    r"\bcurl\b",
    r"\bwget\b",
    r"\bnc\b|\bncat\b|\bnetcat\b",
    r"\bscp\b",
    r"\brsync\b[^|;&]*[:@]",  # remote rsync (user@host: or host:path)
    # --- persistence ---
    r"\blaunchctl\b",
    r"\bcrontab\b",
    r"\bat\s+\d",  # `at 14:00` job scheduling
    r"\.ssh\b",
    r"\.aws\b",
    r"\.gnupg\b",
    r"\bsecurity\s+(find|add|delete|dump-keychain)\b",  # macOS keychain
    r"\bssh-keygen\b",
    # --- piped execution of decoded payloads ---
    r"\bbase64\s+(-d|--decode)\b[^|]*\|\s*(ba|z|da)?sh\b",
    r"\|\s*(ba|z|da)?sh\b",  # anything piped into a shell
]


def check_command(command: str) -> str | None:
    """Return the matched deny pattern, or None if the command is safe.

    Callers format their own denial message from the returned pattern. A
    non-string / empty command is treated as safe (the caller is responsible
    for validating that a command exists).
    """
    if not isinstance(command, str) or not command.strip():
        return None
    for pat in DENY_PATTERNS:
        if re.search(pat, command):
            return pat
    return None


def check_path_write(path: str, root: Path) -> str | None:
    """Validate a file-write path stays within `root`.

    Returns a denial reason, or None if the path is safe. Mirrors the worker's
    in-repo write validation: no absolute paths, no `..`, and the resolved
    target must remain under the (resolved) root.
    """
    if not isinstance(path, str) or not path.strip():
        return "empty path"
    rel = Path(path)
    if rel.is_absolute():
        return f"absolute path not allowed: {path}"
    if ".." in rel.parts:
        return f"path traversal not allowed: {path}"
    resolved_root = root.resolve()
    target = (resolved_root / rel).resolve()
    if not target.is_relative_to(resolved_root):
        return f"path escapes workspace root: {path}"
    return None
