"""Tests for the PyHealth project scanner (Stage 2).

All tests use ``tmp_path`` and create their own isolated project trees.
No test depends on the real PyHealth source tree.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from pyhealth.cli import app
from pyhealth.scanner import DEFAULT_LARGE_FILE_THRESHOLD, ProjectScanner

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def make_scanner() -> ProjectScanner:
    """Return a scanner with the default configuration."""
    return ProjectScanner()


# ---------------------------------------------------------------------------
# 1. Empty project
# ---------------------------------------------------------------------------


def test_empty_project(tmp_path: Path) -> None:
    """Scanning an empty directory yields all-zero counts."""
    result = make_scanner().scan(tmp_path)
    assert result.total_files == 0
    assert result.python_files == 0
    assert result.directories == 0
    assert result.total_lines == 0
    assert result.total_size_bytes == 0
    assert result.large_files == []
    assert result.empty_directories == []
    assert result.duplicate_files == []


# ---------------------------------------------------------------------------
# 2. File counting
# ---------------------------------------------------------------------------


def test_file_counting(tmp_path: Path) -> None:
    """total_files counts every file regardless of extension."""
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "b.md").write_text("world")
    (tmp_path / "c.py").write_text("x = 1\n")
    result = make_scanner().scan(tmp_path)
    assert result.total_files == 3


# ---------------------------------------------------------------------------
# 3. Python file counting
# ---------------------------------------------------------------------------


def test_python_file_counting(tmp_path: Path) -> None:
    """python_files counts only .py files."""
    (tmp_path / "script.py").write_text("pass\n")
    (tmp_path / "README.md").write_text("# readme")
    (tmp_path / "data.json").write_text("{}")
    result = make_scanner().scan(tmp_path)
    assert result.python_files == 1
    assert result.total_files == 3


# ---------------------------------------------------------------------------
# 4. Directory counting
# ---------------------------------------------------------------------------


def test_directory_counting(tmp_path: Path) -> None:
    """directories counts non-ignored sub-directories."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "utils").mkdir()
    (tmp_path / "docs").mkdir()
    result = make_scanner().scan(tmp_path)
    assert result.directories == 3  # src, src/utils, docs


# ---------------------------------------------------------------------------
# 5. Line counting
# ---------------------------------------------------------------------------


def test_line_counting(tmp_path: Path) -> None:
    """total_lines sums physical lines across all Python files."""
    (tmp_path / "a.py").write_text("line1\nline2\nline3\n")  # 3 lines
    (tmp_path / "b.py").write_text("x = 1\n")  # 1 line
    (tmp_path / "notes.txt").write_text("ignored\nignored\n")  # not .py
    result = make_scanner().scan(tmp_path)
    assert result.total_lines == 4


# ---------------------------------------------------------------------------
# 6. Project size
# ---------------------------------------------------------------------------


def test_project_size(tmp_path: Path) -> None:
    """total_size_bytes is the sum of all file sizes."""
    (tmp_path / "small.txt").write_bytes(b"a" * 100)
    (tmp_path / "medium.bin").write_bytes(b"b" * 900)
    result = make_scanner().scan(tmp_path)
    assert result.total_size_bytes == 1000


# ---------------------------------------------------------------------------
# 7. Ignored directories
# ---------------------------------------------------------------------------


def test_ignored_directories_are_skipped(tmp_path: Path) -> None:
    """Files inside ignored directories must not appear in any count."""
    ignored_names = [
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
    ]
    for name in ignored_names:
        d = tmp_path / name
        d.mkdir()
        (d / "secret.py").write_text("x = 1\n")
        (d / "data.txt").write_text("data")

    # One real file so the scan is non-trivial.
    (tmp_path / "main.py").write_text("print('hi')\n")

    result = make_scanner().scan(tmp_path)
    assert result.total_files == 1
    assert result.python_files == 1
    assert result.directories == 0


# ---------------------------------------------------------------------------
# 8. Large files
# ---------------------------------------------------------------------------


def test_large_file_detection(tmp_path: Path) -> None:
    """Files exceeding the threshold are reported in large_files."""
    threshold = DEFAULT_LARGE_FILE_THRESHOLD
    small = tmp_path / "small.bin"
    large = tmp_path / "large.bin"
    small.write_bytes(b"x" * threshold)          # exactly threshold → NOT large
    large.write_bytes(b"x" * (threshold + 1))    # one byte over → large

    result = make_scanner().scan(tmp_path)
    assert large in result.large_files
    assert small not in result.large_files


def test_large_file_custom_threshold(tmp_path: Path) -> None:
    """The threshold is configurable per-scanner instance."""
    custom_threshold = 512
    (tmp_path / "big.bin").write_bytes(b"x" * (custom_threshold + 1))
    result = ProjectScanner(large_file_threshold=custom_threshold).scan(tmp_path)
    assert len(result.large_files) == 1


# ---------------------------------------------------------------------------
# 9. Empty directories
# ---------------------------------------------------------------------------


def test_empty_directory_detection(tmp_path: Path) -> None:
    """Directories with no non-ignored contents are reported."""
    (tmp_path / "empty_dir").mkdir()
    (tmp_path / "non_empty_dir").mkdir()
    (tmp_path / "non_empty_dir" / "file.txt").write_text("data")

    result = make_scanner().scan(tmp_path)
    empty_names = {p.name for p in result.empty_directories}
    assert "empty_dir" in empty_names
    assert "non_empty_dir" not in empty_names


# ---------------------------------------------------------------------------
# 10. Duplicate files
# ---------------------------------------------------------------------------


def test_duplicate_file_detection(tmp_path: Path) -> None:
    """Files with identical content are grouped as duplicates."""
    content = b"duplicate content here"
    (tmp_path / "copy_a.txt").write_bytes(content)
    (tmp_path / "copy_b.txt").write_bytes(content)
    (tmp_path / "unique.txt").write_bytes(b"something different")

    result = make_scanner().scan(tmp_path)
    assert len(result.duplicate_files) == 1
    dup_names = {p.name for p in result.duplicate_files[0]}
    assert dup_names == {"copy_a.txt", "copy_b.txt"}


# ---------------------------------------------------------------------------
# 11. Same filename, different content → NOT a duplicate
# ---------------------------------------------------------------------------


def test_same_filename_different_content_not_duplicate(tmp_path: Path) -> None:
    """Files with the same name but different content are not duplicates."""
    sub_a = tmp_path / "a"
    sub_b = tmp_path / "b"
    sub_a.mkdir()
    sub_b.mkdir()
    (sub_a / "config.txt").write_text("alpha config")
    (sub_b / "config.txt").write_text("beta config")

    result = make_scanner().scan(tmp_path)
    assert result.duplicate_files == []


# ---------------------------------------------------------------------------
# 12. Invalid path
# ---------------------------------------------------------------------------


def test_invalid_path_raises(tmp_path: Path) -> None:
    """Scanning a non-existent path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        make_scanner().scan(tmp_path / "does_not_exist")


def test_file_as_path_raises(tmp_path: Path) -> None:
    """Scanning a file instead of a directory raises NotADirectoryError."""
    f = tmp_path / "file.txt"
    f.write_text("hello")
    with pytest.raises(NotADirectoryError):
        make_scanner().scan(f)


# ---------------------------------------------------------------------------
# 13. CLI scan
# ---------------------------------------------------------------------------


def test_cli_scan_exit_code(tmp_path: Path) -> None:
    """``pyhealth scan <path>`` exits with code 0 on a valid directory."""
    (tmp_path / "hello.py").write_text("print('hi')\n")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_cli_scan_output_structure(tmp_path: Path) -> None:
    """CLI scan output contains the expected section headers and markers."""
    (tmp_path / "main.py").write_text("x = 1\ny = 2\n")
    (tmp_path / "README.md").write_text("# readme")

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in result.output
    assert "PROJECT STATISTICS" in result.output
    assert "PROJECT STRUCTURE" in result.output
    assert "Scan completed successfully" in result.output


def test_cli_scan_invalid_path(tmp_path: Path) -> None:
    """CLI scan on a missing path exits non-zero and shows an error message."""
    bad = str(tmp_path / "no_such_dir")
    result = runner.invoke(app, ["scan", bad])
    assert result.exit_code != 0
    assert "Error" in result.output
