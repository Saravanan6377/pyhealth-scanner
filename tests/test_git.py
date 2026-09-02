"""Tests for Stage 8: Git Health Analyzer."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

import pyhealth
from pyhealth.analyzers.git import GitAnalyzer
from pyhealth.cli import app
from pyhealth.models import GitResult, Severity

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1. GitResult construction
# ---------------------------------------------------------------------------


def test_git_result_construction() -> None:
    """GitResult dataclass initializes with default values."""
    res = GitResult()
    assert res.repository_detected is False
    assert res.gitignore_exists is False
    assert res.tracked_files_count == 0
    assert res.untracked_files_count == 0
    assert res.large_tracked_files == []
    assert res.sensitive_tracked_files == []
    assert res.branch_name is None
    assert res.commit_count is None
    assert res.issues == []
    assert res.total_findings == 0


# ---------------------------------------------------------------------------
# 2-3. Non-Git directory and repository detection
# ---------------------------------------------------------------------------


def test_non_git_directory(tmp_path: Path) -> None:
    """Non-git directory reports repository_detected=False without crashing."""
    with patch.object(GitAnalyzer, "_run_git", return_value=None):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.repository_detected is False
        assert res.tracked_files_count == 0


def test_git_repository_detection(tmp_path: Path) -> None:
    """Detection of .git directory returns repository_detected=True."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    with patch.object(GitAnalyzer, "_run_git", return_value=None):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.repository_detected is True
        assert res.repo_root == tmp_path


# ---------------------------------------------------------------------------
# 4-5. .gitignore presence and missing
# ---------------------------------------------------------------------------


def test_gitignore_present(tmp_path: Path) -> None:
    """Presence of .gitignore avoids PYH401."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    with patch.object(GitAnalyzer, "_run_git", return_value=None):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.gitignore_exists is True
        assert not any(i.code == "PYH401" for i in res.issues)


def test_gitignore_missing(tmp_path: Path) -> None:
    """Missing .gitignore emits PYH401 with LOW severity."""
    (tmp_path / ".git").mkdir()
    with patch.object(GitAnalyzer, "_run_git", return_value=None):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.gitignore_exists is False
        pyh401 = [i for i in res.issues if i.code == "PYH401"]
        assert len(pyh401) == 1
        assert pyh401[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# 6-7. Untracked and tracked file counting
# ---------------------------------------------------------------------------


def test_untracked_file_detection(tmp_path: Path) -> None:
    """Untracked files are correctly parsed from NUL-delimited git output."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "ls-files --others" in cmd:
            proc.stdout = "a.py\0b.py\0c.txt\0"
        else:
            proc.stdout = ""
        return proc

    with patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.untracked_files_count == 3


def test_tracked_file_counting(tmp_path: Path) -> None:
    """Tracked files are correctly parsed from NUL-delimited git output."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "ls-files -z" in cmd and "--others" not in cmd:
            proc.stdout = "main.py\0utils.py\0README.md\0"
        else:
            proc.stdout = ""
        return proc

    with patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.tracked_files_count == 3


# ---------------------------------------------------------------------------
# 8. Large tracked-file detection
# ---------------------------------------------------------------------------


def test_large_tracked_file_detection(tmp_path: Path) -> None:
    """Tracked file >= 10 MiB produces PYH402 MEDIUM severity issue."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    # Create a dummy large file (we patch os.path.getsize/stat)
    large_file = tmp_path / "data.bin"
    large_file.write_text("large data", encoding="utf-8")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "ls-files -z" in cmd and "--others" not in cmd:
            proc.stdout = "data.bin\0"
        else:
            proc.stdout = ""
        return proc

    # Patch stat().st_size to return 11 MiB
    with (
        patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git),
        patch("pathlib.Path.stat") as mock_stat,
    ):
        mock_stat_res = MagicMock()
        mock_stat_res.st_size = 11 * 1024 * 1024
        mock_stat_res.st_mode = 0o100644
        mock_stat.return_value = mock_stat_res

        res = GitAnalyzer(tmp_path).analyze()
        assert len(res.large_tracked_files) == 1
        pyh402 = [i for i in res.issues if i.code == "PYH402"]
        assert len(pyh402) == 1
        assert pyh402[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# 9-12. Sensitive tracked filename screening
# ---------------------------------------------------------------------------


def test_sensitive_tracked_filename_detection(tmp_path: Path) -> None:
    """Tracked sensitive files produce PYH403 HIGH severity issue."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "ls-files -z" in cmd and "--others" not in cmd:
            proc.stdout = "secrets.json\0config/credentials.json\0"
        else:
            proc.stdout = ""
        return proc

    with patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git):
        res = GitAnalyzer(tmp_path).analyze()
        assert len(res.sensitive_tracked_files) == 2
        pyh403 = [i for i in res.issues if i.code == "PYH403"]
        assert len(pyh403) == 2
        assert pyh403[0].severity == Severity.HIGH


def test_env_file_detection(tmp_path: Path) -> None:
    """Tracked .env or .env.local file is flagged with PYH403."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "ls-files -z" in cmd and "--others" not in cmd:
            proc.stdout = ".env\0config/.env.production\0"
        else:
            proc.stdout = ""
        return proc

    with patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git):
        res = GitAnalyzer(tmp_path).analyze()
        assert len(res.sensitive_tracked_files) == 2
        pyh403 = [i for i in res.issues if i.code == "PYH403"]
        assert len(pyh403) == 2


def test_pem_file_detection(tmp_path: Path) -> None:
    """Tracked .pem, .key, id_rsa files are flagged with PYH403."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "ls-files -z" in cmd and "--others" not in cmd:
            proc.stdout = "certs/server.pem\0keys/id_rsa\0"
        else:
            proc.stdout = ""
        return proc

    with patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git):
        res = GitAnalyzer(tmp_path).analyze()
        assert len(res.sensitive_tracked_files) == 2
        pyh403 = [i for i in res.issues if i.code == "PYH403"]
        assert len(pyh403) == 2


def test_ordinary_tracked_files_not_flagged(tmp_path: Path) -> None:
    """Ordinary tracked files (main.py, README.md) are not flagged as sensitive."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "ls-files -z" in cmd and "--others" not in cmd:
            proc.stdout = "main.py\0README.md\0src/utils.py\0"
        else:
            proc.stdout = ""
        return proc

    with patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.sensitive_tracked_files == []
        assert not any(i.code == "PYH403" for i in res.issues)


# ---------------------------------------------------------------------------
# 13-15. Missing git, branch detection, commit count
# ---------------------------------------------------------------------------


def test_git_missing_handling(tmp_path: Path) -> None:
    """Missing git executable is handled safely without crashing."""
    with patch("shutil.which", return_value=None):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.repository_detected is False


def test_branch_detection(tmp_path: Path) -> None:
    """Current branch name is correctly extracted from git output."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "branch --show-current" in cmd:
            proc.stdout = "main\n"
        else:
            proc.stdout = ""
        return proc

    with patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.branch_name == "main"


def test_commit_count_handling(tmp_path: Path) -> None:
    """Commit count is correctly extracted from git output."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.pyc\n")

    def mock_run_git(args: list[str]) -> MagicMock | None:
        cmd = " ".join(args)
        proc = MagicMock()
        proc.returncode = 0
        if "rev-list --count" in cmd:
            proc.stdout = "42\n"
        else:
            proc.stdout = ""
        return proc

    with patch.object(GitAnalyzer, "_run_git", side_effect=mock_run_git):
        res = GitAnalyzer(tmp_path).analyze()
        assert res.commit_count == 42


# ---------------------------------------------------------------------------
# 16-23. CLI commands and Regression checks
# ---------------------------------------------------------------------------


def test_cli_git_command(tmp_path: Path) -> None:
    """pyhealth git <path> command succeeds and outputs report."""
    res = runner.invoke(app, ["git", str(tmp_path)])
    assert res.exit_code == 0
    assert "GIT HEALTH" in res.output


def test_cli_scan_command_with_git(tmp_path: Path) -> None:
    """pyhealth scan includes GIT HEALTH section."""
    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 0
    assert "GIT HEALTH" in res.output


def test_cli_docs_command_still_works(tmp_path: Path) -> None:
    """Existing docs command continues working."""
    res = runner.invoke(app, ["docs", str(tmp_path)])
    assert res.exit_code == 0
    assert "DOCUMENTATION" in res.output


def test_cli_deps_command_still_works(tmp_path: Path) -> None:
    """Existing deps command continues working."""
    res = runner.invoke(app, ["deps", str(tmp_path)])
    assert res.exit_code == 0
    assert "DEPENDENCIES" in res.output


def test_cli_quality_command_still_works(tmp_path: Path) -> None:
    """Existing quality command continues working."""
    res = runner.invoke(app, ["quality", str(tmp_path)])
    assert res.exit_code == 0
    assert "CODE QUALITY" in res.output


def test_cli_security_command_still_works(tmp_path: Path) -> None:
    """Existing security command continues working."""
    res = runner.invoke(app, ["security", str(tmp_path)])
    assert res.exit_code == 0
    assert "SECURITY" in res.output


def test_cli_complexity_command_still_works(tmp_path: Path) -> None:
    """Existing complexity command continues working."""
    res = runner.invoke(app, ["complexity", str(tmp_path)])
    assert res.exit_code == 0
    assert "COMPLEXITY" in res.output


def test_version_remains_2_0_0() -> None:
    """Version string remains 2.0.0."""
    assert pyhealth.__version__ == "2.0.0"
