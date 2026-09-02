"""Git Health analyzer for PyHealth.

Inspects Git repository state, .gitignore presence, tracked/untracked file counts,
commit history statistics, large tracked files (>= 10 MiB), and sensitive
tracked filenames (.env, *.pem, id_rsa, etc.).

This analyzer is strictly read-only and never modifies repository state.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from pathlib import Path

from pyhealth.models import GitResult, Issue, Severity

_LARGE_FILE_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MiB (10,485,760 bytes)

_SENSITIVE_PATTERNS = (
    ".env",
    ".env.*",
    "credentials.json",
    "secrets.json",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_rsa.*",
    "id_dsa",
    "id_dsa.*",
    "*.p12",
    "*.pfx",
)


def _format_size(size_bytes: int) -> str:
    """Format bytes into a human-readable string (e.g. 18.4 MB or 10.0 MiB)."""
    val = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if val < 1024.0:
            return f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} TB"


class GitAnalyzer:
    """Read-only analyzer for Git repository health and security hygiene.

    Args:
        root: Root directory of the project/path to analyze.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def analyze(self) -> GitResult:
        """Run Git health checks and return aggregated results."""
        issues: list[Issue] = []

        # 1. Repository detection
        repo_detected, repo_root = self._detect_repository()
        if not repo_detected:
            # Check for .gitignore anyway if path exists
            gitignore_exists = (self.root / ".gitignore").is_file()
            if not gitignore_exists:
                issues.append(
                    Issue(
                        category="git",
                        severity=Severity.LOW,
                        code="PYH401",
                        message=".gitignore is missing.",
                        tool="pyhealth",
                        suggestion="Add a suitable .gitignore for Python projects.",
                    )
                )
            return GitResult(
                repository_detected=False,
                gitignore_exists=gitignore_exists,
                repo_root=None,
                issues=issues,
            )

        # 2. .gitignore check
        gitignore_exists = (self.root / ".gitignore").is_file() or (
            repo_root is not None and (repo_root / ".gitignore").is_file()
        )
        if not gitignore_exists:
            issues.append(
                Issue(
                    category="git",
                    severity=Severity.LOW,
                    code="PYH401",
                    message=".gitignore is missing.",
                    tool="pyhealth",
                    suggestion="Add a suitable .gitignore for Python projects.",
                )
            )

        # 3. Safe Git command execution
        tracked_files = self._get_tracked_files()
        untracked_files = self._get_untracked_files()
        branch_name = self._get_branch_name()
        commit_count = self._get_commit_count()

        # 4. Large tracked files check (>= 10 MiB)
        large_tracked: list[tuple[str, int]] = []
        for rel_str in tracked_files:
            abs_path = self.root / rel_str
            try:
                if abs_path.is_file():
                    size = abs_path.stat().st_size
                    if size >= _LARGE_FILE_THRESHOLD_BYTES:
                        large_tracked.append((rel_str, size))
                        size_str = _format_size(size)
                        issues.append(
                            Issue(
                                category="git",
                                severity=Severity.MEDIUM,
                                code="PYH402",
                                message=f"Large tracked file: {rel_str} ({size_str})",
                                file=rel_str,
                                tool="pyhealth",
                                suggestion=(
                                    "Consider Git LFS or another large-file strategy."
                                ),
                            )
                        )
            except OSError:
                continue

        # 5. Sensitive tracked file screening
        sensitive_tracked: list[str] = []
        for rel_str in tracked_files:
            if self._is_sensitive_filename(rel_str):
                sensitive_tracked.append(rel_str)
                issues.append(
                    Issue(
                        category="git",
                        severity=Severity.HIGH,
                        code="PYH403",
                        message=(
                            f"Potentially sensitive file is tracked by Git: {rel_str}"
                        ),
                        file=rel_str,
                        tool="pyhealth",
                        suggestion=(
                            "Remove sensitive files from version control and "
                            "rotate any credentials that may have been exposed."
                        ),
                    )
                )

        return GitResult(
            repository_detected=True,
            gitignore_exists=gitignore_exists,
            repo_root=repo_root,
            tracked_files_count=len(tracked_files),
            untracked_files_count=len(untracked_files),
            large_tracked_files=large_tracked,
            sensitive_tracked_files=sensitive_tracked,
            branch_name=branch_name,
            commit_count=commit_count,
            issues=issues,
        )

    def _detect_repository(self) -> tuple[bool, Path | None]:
        """Detect whether path is inside a Git repository or worktree."""
        git_dir = self.root / ".git"
        if git_dir.exists():
            return True, self.root

        # Try git rev-parse
        proc = self._run_git(["rev-parse", "--is-inside-worktree"])
        if proc is not None and proc.returncode == 0 and proc.stdout.strip() == "true":
            root_proc = self._run_git(["rev-parse", "--show-toplevel"])
            if root_proc is not None and root_proc.returncode == 0:
                root_path_str = root_proc.stdout.strip()
                if root_path_str:
                    return True, Path(root_path_str)
            return True, None

        return False, None

    def _get_tracked_files(self) -> list[str]:
        """Return NUL-delimited list of tracked relative file paths."""
        proc = self._run_git(["ls-files", "-z", "--", "."])
        if proc is None or proc.returncode != 0:
            return []
        raw_paths = proc.stdout.split("\0")
        return [p for p in raw_paths if p]

    def _get_untracked_files(self) -> list[str]:
        """Return NUL-delimited list of untracked relative file paths."""
        proc = self._run_git(
            ["ls-files", "--others", "--exclude-standard", "-z", "--", "."]
        )
        if proc is None or proc.returncode != 0:
            return []
        raw_paths = proc.stdout.split("\0")
        return [p for p in raw_paths if p]

    def _get_branch_name(self) -> str | None:
        """Return the current branch name, or None."""
        proc = self._run_git(["branch", "--show-current"])
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()

        # Fallback to rev-parse
        proc_rev = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        if proc_rev is not None and proc_rev.returncode == 0:
            val = proc_rev.stdout.strip()
            if val and val != "HEAD":
                return val
        return None

    def _get_commit_count(self) -> int | None:
        """Return the total commit count for HEAD, or None."""
        proc = self._run_git(["rev-list", "--count", "HEAD"])
        if proc is not None and proc.returncode == 0:
            try:
                return int(proc.stdout.strip())
            except ValueError:
                return None
        return None

    def _is_sensitive_filename(self, rel_path_str: str) -> bool:
        """Check if relative path matches sensitive filename patterns."""
        normalized_path = rel_path_str.replace("\\", "/")
        filename = os.path.basename(normalized_path)

        for pattern in _SENSITIVE_PATTERNS:
            if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(
                normalized_path, pattern
            ):
                return True
        return False

    def _run_git(self, args: list[str]) -> subprocess.CompletedProcess[str] | None:
        """Run git executable safely via subprocess without shell=True."""
        git_exe = shutil.which("git")
        if not git_exe:
            return None

        cmd = [git_exe] + args
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.root),
                timeout=10,
            )
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            return None
