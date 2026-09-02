"""Project scanner implementation for PyHealth.

This module is the only place where file-system traversal happens.
All later analysers must import :data:`IGNORED_DIRS` from here so that
the exclusion list is kept in a single authoritative location.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from pyhealth.models import ScanResult

# ---------------------------------------------------------------------------
# Public constants — re-used by every future analyser
# ---------------------------------------------------------------------------

#: Directories excluded from all scans.
IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "node_modules",
        "build",
        "dist",
    }
)

#: Default large-file threshold: 1 MB.
DEFAULT_LARGE_FILE_THRESHOLD: int = 1 * 1024 * 1024


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class ProjectScanner:
    """Scans a project directory and collects structural health metrics.

    Args:
        large_file_threshold: Files strictly larger than this many bytes are
            flagged as large.  Defaults to :data:`DEFAULT_LARGE_FILE_THRESHOLD`
            (1 MB).

    Example::

        from pathlib import Path
        from pyhealth.scanner import ProjectScanner

        result = ProjectScanner().scan(Path("."))
        print(result.total_files)
    """

    def __init__(
        self,
        large_file_threshold: int = DEFAULT_LARGE_FILE_THRESHOLD,
    ) -> None:
        self.large_file_threshold = large_file_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, path: Path) -> ScanResult:
        """Scan *path* and return a populated :class:`~pyhealth.models.ScanResult`.

        Args:
            path: Root directory to scan.  May be absolute or relative.

        Returns:
            A :class:`~pyhealth.models.ScanResult` containing all collected
            metrics.

        Raises:
            FileNotFoundError: If *path* does not exist.
            NotADirectoryError: If *path* exists but is not a directory.
        """
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")
        if not path.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {path}")

        total_files: int = 0
        python_files: int = 0
        directories: int = 0
        total_lines: int = 0
        total_size_bytes: int = 0
        large_files: list[Path] = []
        empty_directories: list[Path] = []

        # Map file size → list of paths; used for duplicate detection.
        size_map: defaultdict[int, list[Path]] = defaultdict(list)

        for item in self._walk(path):
            if item.is_dir():
                directories += 1
                if self._is_empty_dir(item):
                    empty_directories.append(item)
            elif item.is_file():
                total_files += 1
                try:
                    size = item.stat().st_size
                except OSError:
                    size = 0

                total_size_bytes += size
                size_map[size].append(item)

                if size > self.large_file_threshold:
                    large_files.append(item)

                if item.suffix == ".py":
                    python_files += 1
                    total_lines += self._count_lines(item)

        return ScanResult(
            project_path=path,
            total_files=total_files,
            python_files=python_files,
            directories=directories,
            total_lines=total_lines,
            total_size_bytes=total_size_bytes,
            large_files=large_files,
            empty_directories=empty_directories,
            duplicate_files=self._find_duplicates(size_map),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _walk(self, path: Path) -> Iterator[Path]:
        """Recursively yield every non-ignored entry under *path*.

        Directories in :data:`IGNORED_DIRS` are skipped in their entirety;
        their children are never visited.  A :exc:`PermissionError` on any
        directory is silently swallowed so that one inaccessible folder does
        not abort the whole scan.
        """
        try:
            entries = sorted(path.iterdir())
        except PermissionError:
            return

        for entry in entries:
            if entry.is_dir():
                if entry.name in IGNORED_DIRS:
                    continue
                yield entry
                yield from self._walk(entry)
            else:
                yield entry

    def _is_empty_dir(self, path: Path) -> bool:
        """Return ``True`` when *path* contains no non-ignored entries.

        A directory that contains *only* ignored sub-directories is treated as
        effectively empty from PyHealth's perspective.
        """
        try:
            for entry in path.iterdir():
                if entry.is_dir() and entry.name in IGNORED_DIRS:
                    continue
                return False
        except PermissionError:
            # Cannot inspect: assume not empty to avoid false positives.
            return False
        return True

    def _count_lines(self, path: Path) -> int:
        """Return the physical line count of a Python file.

        Encoding errors are replaced with the Unicode replacement character so
        that a single malformed file does not abort the scan.  Any
        :exc:`OSError` (e.g. permission denied) returns ``0``.
        """
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                return sum(1 for _ in fh)
        except OSError:
            return 0

    def _find_duplicates(
        self,
        size_map: defaultdict[int, list[Path]],
    ) -> list[list[Path]]:
        """Return groups of files that share identical byte content.

        Detection strategy:

        1. Only files that share the *same size* are compared (fast pre-filter).
        2. A SHA-256 digest is computed for each candidate.
        3. Files with identical digests form a duplicate group.

        Groups are sorted for deterministic output.
        """
        duplicates: list[list[Path]] = []

        for paths in size_map.values():
            if len(paths) < 2:
                continue

            hash_map: defaultdict[str, list[Path]] = defaultdict(list)
            for p in paths:
                digest = self._sha256(p)
                if digest is not None:
                    hash_map[digest].append(p)

            for group in hash_map.values():
                if len(group) > 1:
                    duplicates.append(sorted(group))

        return duplicates

    @staticmethod
    def _sha256(path: Path) -> str | None:
        """Return the SHA-256 hex digest of *path*, or ``None`` on any error.

        Reads the file in 64 KB chunks to keep memory usage bounded even for
        large files.
        """
        hasher = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    hasher.update(chunk)
        except OSError:
            return None
        return hasher.hexdigest()
