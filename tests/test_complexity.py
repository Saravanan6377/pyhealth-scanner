"""Tests for the PyHealth complexity analyser (Stage 5).

All tests use isolated project trees via ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pyhealth.analyzers.complexity import ComplexityAnalyzer
from pyhealth.cli import app
from pyhealth.models import ComplexityResult, Issue, Severity

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1. ComplexityResult creation
# ---------------------------------------------------------------------------


def test_complexity_result_creation() -> None:
    """ComplexityResult fields are stored correctly."""
    result = ComplexityResult(
        python_files=5,
        issues=[],
        functions_analyzed=12,
        classes_analyzed=2,
        average_complexity=3.5,
        max_complexity=8,
        maintainability_index=85.0,
        high_complexity_findings=0,
    )
    assert result.python_files == 5
    assert result.total_findings == 0
    assert result.functions_analyzed == 12
    assert result.classes_analyzed == 2
    assert result.average_complexity == 3.5
    assert result.max_complexity == 8
    assert result.maintainability_index == 85.0
    assert result.high_complexity_findings == 0


# ---------------------------------------------------------------------------
# 2. Severity counts
# ---------------------------------------------------------------------------


def test_complexity_severity_counts() -> None:
    """severity_counts correctly aggregates findings by severity."""
    issues = [
        Issue(
            category="complexity",
            severity=Severity.HIGH,
            code="PYH101",
            message="cc 15",
        ),
        Issue(
            category="complexity",
            severity=Severity.MEDIUM,
            code="PYH101",
            message="cc 12",
        ),
    ]
    result = ComplexityResult(python_files=2, issues=issues)
    assert result.total_findings == 2
    counts = result.severity_counts
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.MEDIUM] == 1
    assert counts[Severity.LOW] == 0


# ---------------------------------------------------------------------------
# 3. Low-complexity function
# ---------------------------------------------------------------------------


def test_low_complexity_function(tmp_path: Path) -> None:
    """Simple function with complexity <= 4 produces no PYH101 issue."""
    code = "def simple():\n    return 42\n"
    (tmp_path / "simple.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert result.functions_analyzed == 1
    assert result.high_complexity_findings == 0
    assert len(result.issues) == 0


# ---------------------------------------------------------------------------
# 4. Function at threshold
# ---------------------------------------------------------------------------


def test_function_at_threshold(tmp_path: Path) -> None:
    """Function with complexity == max_cyclomatic_complexity produces no issue."""
    # 9 ifs + base 1 = complexity 10
    code = "def func_at_10(x):\n" + "".join(
        f"    if x == {i}:\n        return {i}\n" for i in range(9)
    )
    (tmp_path / "at_10.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path, max_cyclomatic_complexity=10).analyze()

    assert result.functions_analyzed == 1
    assert result.max_complexity == 10
    assert result.high_complexity_findings == 0
    assert len(result.issues) == 0


# ---------------------------------------------------------------------------
# 5. Function above threshold
# ---------------------------------------------------------------------------


def test_function_above_threshold(tmp_path: Path) -> None:
    """Function with complexity > max_cyclomatic_complexity produces PYH101 issue."""
    # 10 ifs + base 1 = complexity 11
    code = "def func_11(x):\n" + "".join(
        f"    if x == {i}:\n        return {i}\n" for i in range(10)
    )
    (tmp_path / "above.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path, max_cyclomatic_complexity=10).analyze()

    assert result.functions_analyzed == 1
    assert result.max_complexity == 11
    assert result.high_complexity_findings == 1
    pyh101 = [i for i in result.issues if i.code == "PYH101"]
    assert len(pyh101) == 1
    assert pyh101[0].severity == Severity.MEDIUM
    assert "func_11" in pyh101[0].message


# ---------------------------------------------------------------------------
# 6. Nested conditional complexity
# ---------------------------------------------------------------------------


def test_nested_conditional_complexity(tmp_path: Path) -> None:
    """Nested control flow statements increase cyclomatic complexity."""
    code = (
        "def complex_nested(a, b, c):\n"
        "    if a:\n"
        "        for i in range(10):\n"
        "            if b:\n"
        "                while c:\n"
        "                    if a and b:\n"
        "                        pass\n"
    )
    (tmp_path / "nested.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert result.functions_analyzed == 1
    assert result.max_complexity > 1


# ---------------------------------------------------------------------------
# 7. Async function complexity
# ---------------------------------------------------------------------------


def test_async_function_complexity(tmp_path: Path) -> None:
    """Async functions are analysed for complexity."""
    code = (
        "async def fetch_all(urls):\n"
        "    for url in urls:\n"
        "        if url:\n"
        "            pass\n"
    )
    (tmp_path / "async_mod.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert result.functions_analyzed == 1
    assert result.max_complexity == 3


# ---------------------------------------------------------------------------
# 8. Method complexity
# ---------------------------------------------------------------------------


def test_method_complexity(tmp_path: Path) -> None:
    """Methods inside classes are counted and analysed."""
    code = (
        "class Handler:\n"
        "    def handle(self, req):\n"
        "        if req:\n"
        "            return True\n"
        "        return False\n"
    )
    (tmp_path / "handler.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert result.functions_analyzed == 1
    assert result.classes_analyzed == 1


# ---------------------------------------------------------------------------
# 9. Class analysis
# ---------------------------------------------------------------------------


def test_class_analysis(tmp_path: Path) -> None:
    """Classes are counted in classes_analyzed."""
    code = "class A:\n    pass\nclass B:\n    pass\n"
    (tmp_path / "classes.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert result.classes_analyzed == 2


# ---------------------------------------------------------------------------
# 10. Maximum complexity calculation
# ---------------------------------------------------------------------------


def test_maximum_complexity_calculation(tmp_path: Path) -> None:
    """max_complexity returns the highest complexity among all functions."""
    code = (
        "def low():\n"
        "    return 1\n"
        "\n"
        "def high(x):\n"
        "    if x == 1:\n"
        "        return 1\n"
        "    elif x == 2:\n"
        "        return 2\n"
        "    elif x == 3:\n"
        "        return 3\n"
        "    return 0\n"
    )
    (tmp_path / "max_cc.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert result.functions_analyzed == 2
    assert result.max_complexity == 4


# ---------------------------------------------------------------------------
# 11. Average complexity calculation
# ---------------------------------------------------------------------------


def test_average_complexity_calculation(tmp_path: Path) -> None:
    """average_complexity calculates the mean CC rounded to 1 decimal place."""
    code = (
        "def f1():\n"
        "    return 1\n"  # CC = 1
        "\n"
        "def f2(x):\n"
        "    if x:\n"
        "        return 2\n"
        "    return 0\n"  # CC = 2
    )
    (tmp_path / "avg_cc.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert result.functions_analyzed == 2
    assert result.average_complexity == 1.5


# ---------------------------------------------------------------------------
# 12. Maintainability index calculation/normalization
# ---------------------------------------------------------------------------


def test_maintainability_index_calculation(tmp_path: Path) -> None:
    """maintainability_index returns a normalized 0-100 float score."""
    code = "def clean():\n    return 'clean code'\n"
    (tmp_path / "clean.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert 0.0 <= result.maintainability_index <= 100.0


# ---------------------------------------------------------------------------
# 13. Custom complexity threshold
# ---------------------------------------------------------------------------


def test_custom_complexity_threshold(tmp_path: Path) -> None:
    """Custom max_cyclomatic_complexity threshold is respected."""
    # 5 ifs + base 1 = CC 6
    code = "def func_6(x):\n" + "".join(
        f"    if x == {i}:\n        return {i}\n" for i in range(5)
    )
    (tmp_path / "custom.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path, max_cyclomatic_complexity=5).analyze()

    assert result.high_complexity_findings == 1
    pyh101 = [i for i in result.issues if i.code == "PYH101"]
    assert len(pyh101) == 1


# ---------------------------------------------------------------------------
# 14. Ignored directories
# ---------------------------------------------------------------------------


def test_ignored_dirs_complexity(tmp_path: Path) -> None:
    """Ignored directories like .venv and .git are skipped."""
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "complex.py").write_text(
        "def f(x):\n" + "".join(f"    if x == {i}:\n        pass\n" for i in range(15))
    )
    (tmp_path / "main.py").write_text("x = 1\n")

    result = ComplexityAnalyzer(tmp_path).analyze()

    assert result.python_files == 1
    assert result.high_complexity_findings == 0


# ---------------------------------------------------------------------------
# 15. Syntax error handling
# ---------------------------------------------------------------------------


def test_syntax_error_handling(tmp_path: Path) -> None:
    """Syntax errors in files are caught and safely skipped without emitting PYH005."""
    (tmp_path / "bad.py").write_text("def broken(\n")
    (tmp_path / "good.py").write_text("x = 1\n")

    result = ComplexityAnalyzer(tmp_path).analyze()

    pyh005 = [i for i in result.issues if i.code == "PYH005"]
    assert len(pyh005) == 0
    assert result.python_files == 2


# ---------------------------------------------------------------------------
# 16. Missing/invalid source handling
# ---------------------------------------------------------------------------


def test_missing_source_handling(tmp_path: Path) -> None:
    """Unreadable files (e.g. non-existent during walk) do not crash analyzer."""
    analyzer = ComplexityAnalyzer(tmp_path)
    res = analyzer._read_source(tmp_path / "non_existent.py")
    assert res is None


# ---------------------------------------------------------------------------
# 17. Radon integration result conversion
# ---------------------------------------------------------------------------


def test_radon_result_conversion(tmp_path: Path) -> None:
    """PYH101 fields are populated correctly from Radon results."""
    code = "def big_func(x):\n" + "".join(
        f"    if x == {i}:\n        return {i}\n" for i in range(15)
    )
    (tmp_path / "big.py").write_text(code)

    result = ComplexityAnalyzer(tmp_path, max_cyclomatic_complexity=10).analyze()

    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "PYH101"
    assert issue.tool == "radon"
    assert issue.category == "complexity"
    assert issue.line == 1
    assert issue.suggestion is not None


# ---------------------------------------------------------------------------
# 18. pyhealth complexity <tmp-path>
# ---------------------------------------------------------------------------


def test_cli_complexity_command(tmp_path: Path) -> None:
    """``pyhealth complexity PATH`` executes successfully."""
    (tmp_path / "main.py").write_text("def foo():\n    return 1\n")

    res = runner.invoke(app, ["complexity", str(tmp_path)])

    assert res.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in res.output
    assert "COMPLEXITY" in res.output
    assert "Complexity analysis completed" in res.output


# ---------------------------------------------------------------------------
# 19. Existing pyhealth quality <tmp-path>
# ---------------------------------------------------------------------------


def test_cli_quality_command_still_works(tmp_path: Path) -> None:
    """``pyhealth quality PATH`` still works as expected."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["quality", str(tmp_path)])

    assert res.exit_code == 0
    assert "CODE QUALITY" in res.output


# ---------------------------------------------------------------------------
# 20. Existing pyhealth security <tmp-path>
# ---------------------------------------------------------------------------


def test_cli_security_command_still_works(tmp_path: Path) -> None:
    """``pyhealth security PATH`` still works as expected."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["security", str(tmp_path)])

    assert res.exit_code == 0
    assert "SECURITY" in res.output


# ---------------------------------------------------------------------------
# 21. Existing pyhealth scan <tmp-path>
# ---------------------------------------------------------------------------


def test_cli_scan_command_with_complexity(tmp_path: Path) -> None:
    """``pyhealth scan PATH`` includes all report sections including COMPLEXITY."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["scan", str(tmp_path)])

    assert res.exit_code == 0
    assert "PROJECT STATISTICS" in res.output
    assert "CODE QUALITY" in res.output
    assert "SECURITY" in res.output
    assert "COMPLEXITY" in res.output
    assert "Scan completed successfully" in res.output


# ---------------------------------------------------------------------------
# 22. Existing pyhealth version
# ---------------------------------------------------------------------------


def test_version_remains_2_0_0() -> None:
    """Version command displays PyHealth Scanner 2.0.0."""
    res = runner.invoke(app, ["version"])

    assert res.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in res.output
