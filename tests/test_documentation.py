"""Tests for Stage 7: Documentation Analyzer."""

from pathlib import Path

from typer.testing import CliRunner

import pyhealth
from pyhealth.analyzers.documentation import DocumentationAnalyzer
from pyhealth.cli import app
from pyhealth.models import Severity

runner = CliRunner()


def _create_full_docs(tmp_path: Path) -> None:
    """Helper to create complete doc files so file checks pass."""
    readme_content = (
        "# Test Project\n\n"
        "This is a comprehensive test project for PyHealth documentation analysis.\n\n"
        "## Installation\n\n"
        "Run pip install test-project to install the package.\n\n"
        "## Usage\n\n"
        "Import the package and use the main service interface for analysis.\n"
    )
    (tmp_path / "README.md").write_text(readme_content, encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT License", encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog", encoding="utf-8")
    (tmp_path / "CONTRIBUTING.md").write_text("# Contributing", encoding="utf-8")


# ---------------------------------------------------------------------------
# 1-7. File checks (README, LICENSE, CHANGELOG, CONTRIBUTING)
# ---------------------------------------------------------------------------


def test_readme_exists(tmp_path: Path) -> None:
    """Presence of README.md avoids PYH301."""
    _create_full_docs(tmp_path)
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.readme_exists is True
    assert not any(i.code == "PYH301" for i in result.issues)


def test_readme_missing(tmp_path: Path) -> None:
    """Missing README produces PYH301 with HIGH severity."""
    (tmp_path / "LICENSE").write_text("MIT")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.readme_exists is False
    pyh301 = [i for i in result.issues if i.code == "PYH301"]
    assert len(pyh301) == 1
    assert pyh301[0].severity == Severity.HIGH


def test_readme_minimal(tmp_path: Path) -> None:
    """Essentially empty or minimal README produces PYH301 with MEDIUM severity."""
    (tmp_path / "README.md").write_text("# Short\nJust a test.", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT", encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.readme_exists is True
    pyh301 = [i for i in result.issues if i.code == "PYH301"]
    assert len(pyh301) == 1
    assert pyh301[0].severity == Severity.MEDIUM


def test_license_exists(tmp_path: Path) -> None:
    """Presence of LICENSE avoids PYH302."""
    _create_full_docs(tmp_path)
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.license_exists is True
    assert not any(i.code == "PYH302" for i in result.issues)


def test_license_missing(tmp_path: Path) -> None:
    """Missing LICENSE produces PYH302 with HIGH severity."""
    (tmp_path / "README.md").write_text("# Title\nShort description.")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.license_exists is False
    pyh302 = [i for i in result.issues if i.code == "PYH302"]
    assert len(pyh302) == 1
    assert pyh302[0].severity == Severity.HIGH


def test_changelog_missing(tmp_path: Path) -> None:
    """Missing CHANGELOG produces PYH303 with LOW severity."""
    _create_full_docs(tmp_path)
    (tmp_path / "CHANGELOG.md").unlink()
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.changelog_exists is False
    pyh303 = [i for i in result.issues if i.code == "PYH303"]
    assert len(pyh303) == 1
    assert pyh303[0].severity == Severity.LOW


def test_contributing_missing(tmp_path: Path) -> None:
    """Missing CONTRIBUTING produces PYH304 with INFO severity."""
    _create_full_docs(tmp_path)
    (tmp_path / "CONTRIBUTING.md").unlink()
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.contributing_exists is False
    pyh304 = [i for i in result.issues if i.code == "PYH304"]
    assert len(pyh304) == 1
    assert pyh304[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# 8-17. AST / Docstring analysis
# ---------------------------------------------------------------------------


def test_public_module_docstring(tmp_path: Path) -> None:
    """A public module with a top-level docstring is counted as documented."""
    _create_full_docs(tmp_path)
    (tmp_path / "auth.py").write_text('"""Module docstring."""\n', encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.public_modules == 1
    assert result.documented_objects == 1
    assert not any(i.code == "PYH305" for i in result.issues)


def test_missing_module_docstring(tmp_path: Path) -> None:
    """A public non-empty module without a docstring produces PYH305."""
    _create_full_docs(tmp_path)
    (tmp_path / "auth.py").write_text("x = 10\n", encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.public_modules == 1
    pyh305 = [i for i in result.issues if i.code == "PYH305"]
    assert len(pyh305) == 1
    assert "Public module 'auth'" in pyh305[0].message


def test_public_class_docstring(tmp_path: Path) -> None:
    """A public class with a docstring is counted as documented."""
    _create_full_docs(tmp_path)
    code = '"""Module."""\n\nclass User:\n    """User class."""\n    pass\n'
    (tmp_path / "models.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.public_classes == 1
    assert result.documented_objects == 2
    assert not any(i.code == "PYH305" for i in result.issues)


def test_missing_public_class_docstring(tmp_path: Path) -> None:
    """A public class without a docstring produces PYH305."""
    _create_full_docs(tmp_path)
    code = '"""Module."""\n\nclass User:\n    pass\n'
    (tmp_path / "models.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    pyh305 = [i for i in result.issues if i.code == "PYH305"]
    assert any("Public class 'User'" in i.message for i in pyh305)


def test_public_function_docstring(tmp_path: Path) -> None:
    """A top-level public function with a docstring is counted as documented."""
    _create_full_docs(tmp_path)
    code = '"""Module."""\n\ndef login():\n    """Log in user."""\n    pass\n'
    (tmp_path / "auth.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.public_functions == 1
    assert result.documented_objects == 2


def test_missing_public_function_docstring(tmp_path: Path) -> None:
    """A top-level public function without a docstring produces PYH305."""
    _create_full_docs(tmp_path)
    code = '"""Module."""\n\ndef login():\n    pass\n'
    (tmp_path / "auth.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    pyh305 = [i for i in result.issues if i.code == "PYH305"]
    assert any("Public function 'login'" in i.message for i in pyh305)


def test_public_method_docstring(tmp_path: Path) -> None:
    """A public method inside a public class is counted as a public function."""
    _create_full_docs(tmp_path)
    code = (
        '"""Module."""\n\n'
        "class AuthService:\n"
        '    """Auth service."""\n'
        "    def authenticate(self):\n"
        '        """Authenticate user."""\n'
        "        pass\n"
    )
    (tmp_path / "service.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.public_classes == 1
    assert result.public_functions == 1
    assert result.documented_objects == 3


def test_private_function_excluded(tmp_path: Path) -> None:
    """Private functions (starting with _) do not require docstrings."""
    _create_full_docs(tmp_path)
    code = '"""Module."""\n\ndef _internal_helper():\n    pass\n'
    (tmp_path / "utils.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.public_functions == 0
    assert not any(i.code == "PYH305" and "helper" in i.message for i in result.issues)


def test_private_method_excluded(tmp_path: Path) -> None:
    """Private methods starting with _ do not require docstrings."""
    _create_full_docs(tmp_path)
    code = (
        '"""Module."""\n\n'
        "class Engine:\n"
        '    """Engine."""\n'
        "    def _internal_step(self):\n"
        "        pass\n"
    )
    (tmp_path / "engine.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.public_functions == 0
    assert not any(i.code == "PYH305" and "step" in i.message for i in result.issues)


def test_mixed_documented_undocumented_objects(tmp_path: Path) -> None:
    """Mixed documented and undocumented objects calculate counts correctly."""
    _create_full_docs(tmp_path)
    code = (
        '"""Module."""\n\n'
        "def valid():\n"
        '    """Doc."""\n'
        "    pass\n\n"
        "def invalid():\n"
        "    pass\n"
    )
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.public_functions == 2
    assert result.documented_objects == 2  # module doc + valid() doc
    assert len([i for i in result.issues if i.code == "PYH305"]) == 1


# ---------------------------------------------------------------------------
# 18-19. Coverage calculation
# ---------------------------------------------------------------------------


def test_coverage_percentage_calculation(tmp_path: Path) -> None:
    """Docstring coverage percentage is correctly calculated."""
    _create_full_docs(tmp_path)
    # 1 module, 1 class, 1 method (undocumented) -> 2/3 = 66.7%
    code = (
        '"""Module."""\n\n'
        "class Service:\n"
        '    """Service."""\n'
        "    def run(self):\n"
        "        pass\n"
    )
    (tmp_path / "srv.py").write_text(code, encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.docstring_coverage == 66.7


def test_zero_public_objects_handled_safely(tmp_path: Path) -> None:
    """Projects with zero public objects report 100.0% coverage safely."""
    _create_full_docs(tmp_path)
    (tmp_path / "_private.py").write_text("x = 1\n", encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.total_public_objects == 0
    assert result.docstring_coverage == 100.0


# ---------------------------------------------------------------------------
# 20-21. Syntax & Error handling
# ---------------------------------------------------------------------------


def test_syntax_error_does_not_crash_analyzer(tmp_path: Path) -> None:
    """Syntax errors in source files do not crash documentation analysis."""
    _create_full_docs(tmp_path)
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.files_analyzed == 0


def test_syntax_error_does_not_produce_pyh005(tmp_path: Path) -> None:
    """Documentation analyzer does not emit duplicate PYH005 syntax error findings."""
    _create_full_docs(tmp_path)
    (tmp_path / "broken.py").write_text("class (\n", encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert not any(i.code == "PYH005" for i in result.issues)


# ---------------------------------------------------------------------------
# 22-23. Ignored directories
# ---------------------------------------------------------------------------


def test_venv_dir_ignored(tmp_path: Path) -> None:
    """Files inside .venv directory are ignored."""
    _create_full_docs(tmp_path)
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "lib.py").write_text("def hidden(): pass\n", encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.files_analyzed == 0


def test_git_dir_ignored(tmp_path: Path) -> None:
    """Files inside .git directory are ignored."""
    _create_full_docs(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "hook.py").write_text("def hook(): pass\n", encoding="utf-8")
    result = DocumentationAnalyzer(tmp_path).analyze()
    assert result.files_analyzed == 0


# ---------------------------------------------------------------------------
# 24-30. CLI integration & Regression checks
# ---------------------------------------------------------------------------


def test_cli_docs_command(tmp_path: Path) -> None:
    """pyhealth docs <path> command succeeds and displays summary."""
    _create_full_docs(tmp_path)
    res = runner.invoke(app, ["docs", str(tmp_path)])
    assert res.exit_code == 0
    assert "DOCUMENTATION" in res.output
    assert "Docstring coverage" in res.output


def test_cli_scan_command_with_docs(tmp_path: Path) -> None:
    """pyhealth scan includes documentation summary section."""
    _create_full_docs(tmp_path)
    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 0
    assert "DOCUMENTATION" in res.output


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


def test_cli_deps_command_still_works(tmp_path: Path) -> None:
    """Existing deps command continues working."""
    res = runner.invoke(app, ["deps", str(tmp_path)])
    assert res.exit_code == 0
    assert "DEPENDENCIES" in res.output


def test_version_remains_2_0_0() -> None:
    """Version string remains 2.0.0."""
    assert pyhealth.__version__ == "2.0.0"
