"""Tests for the PyHealth code quality analyser (Stage 3).

All tests create isolated project trees via ``tmp_path``.
No test depends on the real PyHealth source tree.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from pyhealth.analyzers.quality import QualityAnalyzer, _ruff_severity
from pyhealth.cli import app
from pyhealth.models import Issue, QualityResult, Severity

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1. Issue model
# ---------------------------------------------------------------------------


def test_issue_model() -> None:
    """Issue fields are stored correctly and the dataclass is frozen."""
    issue = Issue(
        category="quality",
        severity=Severity.HIGH,
        code="F401",
        message="`os` imported but unused",
        file="main.py",
        line=1,
        column=0,
        tool="ruff",
        suggestion="Remove the unused import.",
    )
    assert issue.category == "quality"
    assert issue.severity == Severity.HIGH
    assert issue.code == "F401"
    assert issue.file == "main.py"
    assert issue.line == 1
    assert issue.tool == "ruff"
    assert issue.suggestion == "Remove the unused import."
    # frozen=True — mutation must raise
    try:
        issue.code = "X"  # type: ignore[misc]
        raise AssertionError("Expected FrozenInstanceError")
    except Exception as exc:  # noqa: BLE001
        assert "frozen" in str(exc).lower() or "cannot" in str(exc).lower()


# ---------------------------------------------------------------------------
# 2. Severity
# ---------------------------------------------------------------------------


def test_severity_values() -> None:
    """Severity is a str-enum with the expected string values."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"
    # str-enum: instances compare equal to their string values
    assert Severity.HIGH == "high"


def test_ruff_severity_mapping() -> None:
    """_ruff_severity maps common Ruff prefixes to the correct severity."""
    assert _ruff_severity("F401") == Severity.HIGH
    assert _ruff_severity("E501") == Severity.MEDIUM
    assert _ruff_severity("W291") == Severity.LOW
    assert _ruff_severity("B006") == Severity.HIGH
    assert _ruff_severity("UP001") == Severity.LOW
    assert _ruff_severity("RUF100") == Severity.LOW
    assert _ruff_severity("I001") == Severity.INFO
    assert _ruff_severity("ZZZZ99") == Severity.INFO  # unknown → INFO


# ---------------------------------------------------------------------------
# 3. QualityResult
# ---------------------------------------------------------------------------


def test_quality_result_properties() -> None:
    """total_issues and severity_counts are correctly derived from issues."""
    issues = [
        Issue(category="q", severity=Severity.HIGH, code="X1", message="a"),
        Issue(category="q", severity=Severity.MEDIUM, code="X2", message="b"),
        Issue(category="q", severity=Severity.MEDIUM, code="X3", message="c"),
    ]
    result = QualityResult(python_files=5, issues=issues, ruff_findings=1)
    assert result.total_issues == 3
    sev = result.severity_counts
    assert sev[Severity.HIGH] == 1
    assert sev[Severity.MEDIUM] == 2
    assert sev[Severity.CRITICAL] == 0
    assert sev[Severity.LOW] == 0
    assert sev[Severity.INFO] == 0


# ---------------------------------------------------------------------------
# 4. Long function detection (PYH001)
# ---------------------------------------------------------------------------


def test_long_function_detection(tmp_path: Path) -> None:
    """Functions exceeding max_function_lines are flagged as PYH001."""
    code = "def big_func():\n" + "    x = 1\n" * 82  # 83 lines total
    (tmp_path / "module.py").write_text(code)

    result = QualityAnalyzer(tmp_path).analyze()

    pyh001 = [i for i in result.issues if i.code == "PYH001"]
    assert len(pyh001) == 1
    assert result.long_functions == 1
    assert "big_func" in pyh001[0].message
    assert pyh001[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# 5. Async long function (PYH001)
# ---------------------------------------------------------------------------


def test_async_long_function_detection(tmp_path: Path) -> None:
    """Async functions are subject to the same PYH001 threshold."""
    code = "async def async_func():\n" + "    x = 1\n" * 82
    (tmp_path / "module.py").write_text(code)

    result = QualityAnalyzer(tmp_path).analyze()

    pyh001 = [i for i in result.issues if i.code == "PYH001"]
    assert len(pyh001) == 1
    assert result.long_functions == 1
    assert "async_func" in pyh001[0].message


# ---------------------------------------------------------------------------
# 6. Deep nesting (PYH002)
# ---------------------------------------------------------------------------


def test_deep_nesting_detection(tmp_path: Path) -> None:
    """Nesting depth > max_nesting_depth (default 4) triggers PYH002."""
    code = (
        "def nested_func():\n"
        "    for i in range(10):\n"      # depth 1
        "        for j in range(10):\n"  # depth 2
        "            if True:\n"         # depth 3
        "                while True:\n"  # depth 4
        "                    if True:\n" # depth 5 — exceeds threshold
        "                        pass\n"
    )
    (tmp_path / "module.py").write_text(code)

    result = QualityAnalyzer(tmp_path).analyze()

    pyh002 = [i for i in result.issues if i.code == "PYH002"]
    assert len(pyh002) == 1
    assert result.deep_nesting == 1
    assert "nested_func" in pyh002[0].message
    assert pyh002[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# 7. TODO detection (PYH003)
# ---------------------------------------------------------------------------


def test_todo_detection(tmp_path: Path) -> None:
    """TODO in a comment is flagged as PYH003 with INFO severity."""
    code = "x = 1  # TODO: refactor this\n"
    (tmp_path / "module.py").write_text(code)

    result = QualityAnalyzer(tmp_path).analyze()

    pyh003 = [i for i in result.issues if i.code == "PYH003"]
    assert len(pyh003) == 1
    assert result.todo_fixme_count == 1
    assert pyh003[0].severity == Severity.INFO
    assert "TODO" in pyh003[0].message


# ---------------------------------------------------------------------------
# 8. FIXME detection (PYH003)
# ---------------------------------------------------------------------------


def test_fixme_detection(tmp_path: Path) -> None:
    """FIXME in a comment is flagged as PYH003."""
    code = "# FIXME: this is broken\nx = 2\n"
    (tmp_path / "module.py").write_text(code)

    result = QualityAnalyzer(tmp_path).analyze()

    pyh003 = [i for i in result.issues if i.code == "PYH003"]
    assert len(pyh003) == 1
    assert "FIXME" in pyh003[0].message


# ---------------------------------------------------------------------------
# 9. TODO inside a string literal is NOT detected (PYH003)
# ---------------------------------------------------------------------------


def test_todo_in_string_not_flagged(tmp_path: Path) -> None:
    """TODO/FIXME inside string literals must not produce PYH003 issues."""
    code = (
        'message = "TODO: do this later"\n'
        'status = "FIXME needed"\n'
        "x = 1\n"
    )
    (tmp_path / "module.py").write_text(code)

    result = QualityAnalyzer(tmp_path).analyze()

    pyh003 = [i for i in result.issues if i.code == "PYH003"]
    assert len(pyh003) == 0
    assert result.todo_fixme_count == 0


# ---------------------------------------------------------------------------
# 10. Duplicate function detection (PYH004)
# ---------------------------------------------------------------------------


def test_duplicate_function_detection(tmp_path: Path) -> None:
    """Two functions with structurally identical bodies are flagged as PYH004."""
    shared_body = "    result = x + y\n    return result * 2\n"
    (tmp_path / "a.py").write_text(f"def compute_a(x, y):\n{shared_body}")
    (tmp_path / "b.py").write_text(f"def compute_b(a, b):\n{shared_body}")

    result = QualityAnalyzer(tmp_path).analyze()

    pyh004 = [i for i in result.issues if i.code == "PYH004"]
    assert len(pyh004) >= 1
    assert result.duplicate_function_count >= 1


# ---------------------------------------------------------------------------
# 11. Different implementations are NOT duplicates (PYH004)
# ---------------------------------------------------------------------------


def test_different_functions_not_duplicates(tmp_path: Path) -> None:
    """Functions with different bodies must not be reported as duplicates."""
    code = (
        "def func_a(x, y):\n"
        "    result = x + y\n"
        "    return result * 2\n"
        "\n"
        "def func_b(x, y):\n"
        "    result = x - y\n"   # subtraction vs addition
        "    return result * 2\n"
    )
    (tmp_path / "module.py").write_text(code)

    result = QualityAnalyzer(tmp_path).analyze()

    pyh004 = [i for i in result.issues if i.code == "PYH004"]
    assert len(pyh004) == 0


# ---------------------------------------------------------------------------
# 12. Tiny functions are NOT duplicates (< 2 non-docstring statements)
# ---------------------------------------------------------------------------


def test_tiny_functions_not_flagged_as_duplicates(tmp_path: Path) -> None:
    """Functions with fewer than 2 non-docstring body statements are ignored."""
    (tmp_path / "a.py").write_text("def stub_a():\n    pass\n")
    (tmp_path / "b.py").write_text("def stub_b():\n    pass\n")

    result = QualityAnalyzer(tmp_path).analyze()

    pyh004 = [i for i in result.issues if i.code == "PYH004"]
    assert len(pyh004) == 0


# ---------------------------------------------------------------------------
# 13. Syntax error handling (PYH005)
# ---------------------------------------------------------------------------


def test_syntax_error_produces_pyh005(tmp_path: Path) -> None:
    """A file with invalid syntax gets a PYH005 issue; other files continue."""
    (tmp_path / "bad.py").write_text("def broken(\n")  # missing closing paren
    (tmp_path / "good.py").write_text("x = 1\n")

    result = QualityAnalyzer(tmp_path).analyze()

    pyh005 = [i for i in result.issues if i.code == "PYH005"]
    assert len(pyh005) == 1
    assert pyh005[0].severity == Severity.HIGH
    assert result.python_files == 2  # both files were counted


# ---------------------------------------------------------------------------
# 14. Ignored directories are not analysed
# ---------------------------------------------------------------------------


def test_ignored_dirs_excluded_from_analysis(tmp_path: Path) -> None:
    """Files inside ignored directories must not appear in any count or issue."""
    for ignored_name in ("__pycache__", ".venv", "node_modules"):
        d = tmp_path / ignored_name
        d.mkdir()
        # Long function that would trigger PYH001 if analysed
        (d / "cached.py").write_text("def f():\n" + "    x = 1\n" * 85)

    (tmp_path / "main.py").write_text("x = 1\n")

    result = QualityAnalyzer(tmp_path).analyze()

    assert result.python_files == 1
    assert all(i.code != "PYH001" for i in result.issues)


# ---------------------------------------------------------------------------
# 15. Ruff JSON parsing
# ---------------------------------------------------------------------------


def test_ruff_json_parsing(tmp_path: Path) -> None:
    """Valid Ruff JSON output is parsed into correctly normalised Issues."""
    ruff_json = json.dumps(
        [
            {
                "cell": None,
                "code": "F401",
                "filename": str(tmp_path / "main.py"),
                "location": {"column": 0, "row": 1},
                "end_location": {"column": 9, "row": 1},
                "message": "`os` imported but unused",
                "noqa_row": 1,
                "url": "https://docs.astral.sh/ruff/rules/unused-import",
                "fix": None,
            }
        ]
    )
    mock_proc = MagicMock()
    mock_proc.stdout = ruff_json
    mock_proc.returncode = 1

    with patch(
        "pyhealth.analyzers.quality.subprocess.run", return_value=mock_proc
    ):
        issues = QualityAnalyzer(tmp_path)._run_ruff()

    assert len(issues) == 1
    assert issues[0].code == "F401"
    assert issues[0].tool == "ruff"
    assert issues[0].severity == Severity.HIGH
    assert issues[0].line == 1


# ---------------------------------------------------------------------------
# 16. Non-zero Ruff exit still produces issues when JSON is valid
# ---------------------------------------------------------------------------


def test_ruff_nonzero_exit_still_parses(tmp_path: Path) -> None:
    """Ruff exits non-zero when violations are found; issues must still be parsed."""
    ruff_json = json.dumps(
        [
            {
                "cell": None,
                "code": "E501",
                "filename": str(tmp_path / "a.py"),
                "location": {"column": 89, "row": 5},
                "end_location": {"column": 120, "row": 5},
                "message": "Line too long (120 > 88)",
                "noqa_row": 5,
                "url": "",
                "fix": None,
            }
        ]
    )
    mock_proc = MagicMock()
    mock_proc.stdout = ruff_json
    mock_proc.returncode = 1  # violations found → non-zero exit

    with patch(
        "pyhealth.analyzers.quality.subprocess.run", return_value=mock_proc
    ):
        issues = QualityAnalyzer(tmp_path)._run_ruff()

    assert len(issues) == 1
    assert issues[0].code == "E501"
    assert issues[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# 17. Missing Ruff returns empty list gracefully
# ---------------------------------------------------------------------------


def test_missing_ruff_returns_empty(tmp_path: Path) -> None:
    """FileNotFoundError from subprocess is handled; no exception propagates."""
    with patch(
        "pyhealth.analyzers.quality.subprocess.run",
        side_effect=FileNotFoundError("ruff not found"),
    ):
        issues = QualityAnalyzer(tmp_path)._run_ruff()

    assert issues == []


# ---------------------------------------------------------------------------
# 18. Malformed Ruff JSON returns empty list gracefully
# ---------------------------------------------------------------------------


def test_malformed_ruff_json_returns_empty(tmp_path: Path) -> None:
    """Invalid JSON from Ruff stdout is swallowed; no exception propagates."""
    mock_proc = MagicMock()
    mock_proc.stdout = "this is definitely { not valid } JSON ["
    mock_proc.returncode = 1

    with patch(
        "pyhealth.analyzers.quality.subprocess.run", return_value=mock_proc
    ):
        issues = QualityAnalyzer(tmp_path)._run_ruff()

    assert issues == []


# ---------------------------------------------------------------------------
# 19. pyhealth quality <path>
# ---------------------------------------------------------------------------


def test_cli_quality_command_succeeds(tmp_path: Path) -> None:
    """``pyhealth quality <path>`` exits 0 and includes expected output sections."""
    (tmp_path / "main.py").write_text("x = 1\n")

    result = runner.invoke(app, ["quality", str(tmp_path)])

    assert result.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in result.output
    assert "CODE QUALITY" in result.output
    assert "SEVERITY" in result.output
    assert "Quality analysis completed" in result.output


def test_cli_quality_invalid_path(tmp_path: Path) -> None:
    """``pyhealth quality <missing_path>`` exits non-zero with an error message."""
    result = runner.invoke(app, ["quality", str(tmp_path / "no_such_dir")])

    assert result.exit_code != 0
    assert "Error" in result.output
