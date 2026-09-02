"""Tests for the PyHealth dependency analyser (Stage 6).

All tests use isolated project trees via ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from pyhealth.analyzers.dependencies import DependencyAnalyzer, _clean_req_name
from pyhealth.cli import app
from pyhealth.models import Severity

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1. requirements.txt basic parsing
# ---------------------------------------------------------------------------


def test_requirements_basic_parsing(tmp_path: Path) -> None:
    """requirements.txt with plain package names is parsed correctly."""
    (tmp_path / "requirements.txt").write_text("requests\npandas\nrich\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "requests" in result.declared_dependencies
    assert "pandas" in result.declared_dependencies
    assert "rich" in result.declared_dependencies


# ---------------------------------------------------------------------------
# 2. Requirement version specifiers
# ---------------------------------------------------------------------------


def test_requirement_version_specifiers() -> None:
    """Version specifiers (>=, ==, ~=, <=) are stripped during name cleaning."""
    assert _clean_req_name("requests>=2.0.0") == "requests"
    assert _clean_req_name("pandas==2.2.0") == "pandas"
    assert _clean_req_name("rich~=13.0") == "rich"
    assert _clean_req_name("typer<=0.9.0") == "typer"
    assert _clean_req_name("ruff!=0.4.0") == "ruff"


# ---------------------------------------------------------------------------
# 3. Extras
# ---------------------------------------------------------------------------


def test_requirement_extras() -> None:
    """Requirement extras like [security] are stripped during name cleaning."""
    assert _clean_req_name("requests[security]>=2.0") == "requests"
    assert _clean_req_name("urllib3[socks]") == "urllib3"


# ---------------------------------------------------------------------------
# 4. Comments and blank lines
# ---------------------------------------------------------------------------


def test_comments_and_blank_lines(tmp_path: Path) -> None:
    """Comments, blank lines, and pip options (-r, -e) are ignored."""
    content = (
        "# Production requirements\n"
        "\n"
        "requests>=2.0 # HTTP client\n"
        "-r other.txt\n"
        "  \n"
        "pandas==2.0\n"
    )
    (tmp_path / "requirements.txt").write_text(content)

    result = DependencyAnalyzer(tmp_path).analyze()

    assert result.declared_dependencies == ["pandas", "requests"]


# ---------------------------------------------------------------------------
# 5. pyproject.toml dependencies
# ---------------------------------------------------------------------------


def test_pyproject_toml_dependencies(tmp_path: Path) -> None:
    """[project.dependencies] in pyproject.toml is parsed."""
    pyproject = (
        '[project]\n'
        'name = "myproject"\n'
        'dependencies = [\n'
        '    "requests>=2.0",\n'
        '    "rich>=13.0",\n'
        ']\n'
    )
    (tmp_path / "pyproject.toml").write_text(pyproject)

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "requests" in result.declared_dependencies
    assert "rich" in result.declared_dependencies


# ---------------------------------------------------------------------------
# 6. Optional dependency groups
# ---------------------------------------------------------------------------


def test_optional_dependency_groups(tmp_path: Path) -> None:
    """[project.optional-dependencies] in pyproject.toml are parsed as dev/optional."""
    pyproject = (
        '[project]\n'
        'dependencies = ["requests"]\n'
        '[project.optional-dependencies]\n'
        'dev = ["pytest", "ruff"]\n'
    )
    (tmp_path / "pyproject.toml").write_text(pyproject)

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "requests" in result.declared_dependencies
    # dev dependencies should NOT be listed as potentially unused in app code
    assert "pytest" not in result.potentially_unused
    assert "ruff" not in result.potentially_unused


# ---------------------------------------------------------------------------
# 7. setup.cfg
# ---------------------------------------------------------------------------


def test_setup_cfg_parsing(tmp_path: Path) -> None:
    """install_requires and extras_require in setup.cfg are parsed."""
    setup_cfg = (
        "[options]\n"
        "install_requires =\n"
        "    requests>=2.0\n"
        "    pandas\n"
        "[options.extras_require]\n"
        "dev =\n"
        "    pytest\n"
    )
    (tmp_path / "setup.cfg").write_text(setup_cfg)

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "requests" in result.declared_dependencies
    assert "pandas" in result.declared_dependencies


# ---------------------------------------------------------------------------
# 8. setup.py static behavior
# ---------------------------------------------------------------------------


def test_setup_py_static_parsing(tmp_path: Path) -> None:
    """install_requires in setup.py is parsed statically without code execution."""
    setup_py = (
        'from setuptools import setup\n'
        'setup(\n'
        '    name="foo",\n'
        '    install_requires=["requests>=2.0", "rich"],\n'
        ')\n'
    )
    (tmp_path / "setup.py").write_text(setup_py)

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "requests" in result.declared_dependencies
    assert "rich" in result.declared_dependencies


# ---------------------------------------------------------------------------
# 9. Standard-library imports ignored
# ---------------------------------------------------------------------------


def test_stdlib_imports_ignored(tmp_path: Path) -> None:
    """Standard library modules (os, sys, pathlib, json) are not flagged as missing."""
    code = "import os\nimport sys\nfrom pathlib import Path\nimport json\n"
    (tmp_path / "main.py").write_text(code)

    result = DependencyAnalyzer(tmp_path).analyze()

    assert result.potentially_missing == []
    assert "os" not in result.imported_packages
    assert "sys" not in result.imported_packages


# ---------------------------------------------------------------------------
# 10. Third-party imports detected
# ---------------------------------------------------------------------------


def test_third_party_imports_detected(tmp_path: Path) -> None:
    """Third-party imports (requests, pandas) are detected from AST."""
    code = "import requests\nfrom pandas import DataFrame\n"
    (tmp_path / "app.py").write_text(code)

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "requests" in result.imported_packages
    assert "pandas" in result.imported_packages


# ---------------------------------------------------------------------------
# 11. Local project imports ignored
# ---------------------------------------------------------------------------


def test_local_project_imports_ignored(tmp_path: Path) -> None:
    """Imports of local modules or packages are not flagged as missing external deps."""
    pkg_dir = tmp_path / "mypackage"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    (pkg_dir / "utils.py").write_text("def helper(): pass\n")
    (tmp_path / "main.py").write_text("from mypackage.utils import helper\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "mypackage" not in result.potentially_missing


# ---------------------------------------------------------------------------
# 12. Common import/distribution mappings
# ---------------------------------------------------------------------------


def test_common_import_distribution_mappings(tmp_path: Path) -> None:
    """Imports like PIL or yaml map to distribution names Pillow or PyYAML."""
    (tmp_path / "requirements.txt").write_text("Pillow\nPyYAML\n")
    (tmp_path / "app.py").write_text("import PIL\nimport yaml\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "pillow" not in result.potentially_missing
    assert "pyyaml" not in result.potentially_missing
    assert result.potentially_unused == []


# ---------------------------------------------------------------------------
# 13. Potentially unused dependency detection (PYH201)
# ---------------------------------------------------------------------------


def test_potentially_unused_dependency(tmp_path: Path) -> None:
    """Declared production requirement not found in imports produces PYH201."""
    (tmp_path / "requirements.txt").write_text("requests\nnumpy\n")
    (tmp_path / "main.py").write_text("import requests\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "numpy" in result.potentially_unused
    pyh201 = [i for i in result.issues if i.code == "PYH201"]
    assert len(pyh201) == 1
    assert "numpy" in pyh201[0].message
    assert pyh201[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# 14. Potentially missing dependency detection (PYH202)
# ---------------------------------------------------------------------------


def test_potentially_missing_dependency(tmp_path: Path) -> None:
    """Third-party import not declared in requirement files produces PYH202."""
    (tmp_path / "requirements.txt").write_text("requests\n")
    (tmp_path / "main.py").write_text("import requests\nimport pandas\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "pandas" in result.potentially_missing
    pyh202 = [i for i in result.issues if i.code == "PYH202"]
    assert len(pyh202) == 1
    assert "pandas" in pyh202[0].message
    assert pyh202[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# 15. Dev dependencies not marked unused
# ---------------------------------------------------------------------------


def test_dev_dependencies_not_marked_unused(tmp_path: Path) -> None:
    """Dependencies in requirements-dev.txt are not marked as unused."""
    (tmp_path / "requirements.txt").write_text("requests\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest\nruff\n")
    (tmp_path / "main.py").write_text("import requests\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "pytest" not in result.potentially_unused
    assert "ruff" not in result.potentially_unused


# ---------------------------------------------------------------------------
# 16. Optional dependencies handled conservatively
# ---------------------------------------------------------------------------


def test_optional_dependencies_conservative(tmp_path: Path) -> None:
    """Optional dependencies in pyproject.toml are not marked as unused."""
    pyproject = (
        '[project]\n'
        'dependencies = ["requests"]\n'
        '[project.optional-dependencies]\n'
        'security = ["cryptography"]\n'
    )
    (tmp_path / "pyproject.toml").write_text(pyproject)
    (tmp_path / "main.py").write_text("import requests\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "cryptography" not in result.potentially_unused


# ---------------------------------------------------------------------------
# 17. Installed version detection
# ---------------------------------------------------------------------------


def test_installed_version_detection(tmp_path: Path) -> None:
    """Installed distribution versions are looked up via importlib.metadata."""
    (tmp_path / "requirements.txt").write_text("typer\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "typer" in result.installed_packages
    assert result.installed_packages["typer"] != ""


# ---------------------------------------------------------------------------
# 18. Missing installed package handled safely
# ---------------------------------------------------------------------------


def test_missing_installed_package_handled_safely(tmp_path: Path) -> None:
    """Non-existent installed package is handled safely without crashing."""
    (tmp_path / "requirements.txt").write_text("non_existent_fake_package_999\n")

    result = DependencyAnalyzer(tmp_path).analyze()

    assert "non_existent_fake_package_999" not in result.installed_packages


# ---------------------------------------------------------------------------
# 19. Machine-readable audit output converted into Issue (PYH203)
# ---------------------------------------------------------------------------


def test_pip_audit_json_conversion(tmp_path: Path) -> None:
    """pip-audit JSON output is converted into PYH203 Issue objects."""
    audit_data = {
        "dependencies": [
            {
                "name": "insecure-pkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "GHSA-1234",
                        "summary": "Remote code execution",
                        "fix_versions": ["1.0.1"],
                    }
                ],
            }
        ]
    }
    mock_proc = MagicMock()
    mock_proc.stdout = json.dumps(audit_data)
    mock_proc.returncode = 1

    patch_target = "pyhealth.analyzers.dependencies.subprocess.run"
    with patch(patch_target, return_value=mock_proc):
        issues, count = DependencyAnalyzer(tmp_path)._run_pip_audit({"pkg": "1"})

    assert count == 1
    assert len(issues) == 1
    assert issues[0].code == "PYH203"
    assert issues[0].severity == Severity.HIGH
    assert "insecure-pkg" in issues[0].message
    assert "GHSA-1234" in issues[0].message


# ---------------------------------------------------------------------------
# 20. Audit findings exit status handled
# ---------------------------------------------------------------------------


def test_pip_audit_nonzero_exit_status(tmp_path: Path) -> None:
    """pip-audit non-zero returncode on findings is handled cleanly."""
    audit_data = {
        "dependencies": [
            {
                "name": "vulnerable-lib",
                "version": "2.0.0",
                "vulns": [{"id": "CVE-2024-0001", "summary": "Buffer overflow"}],
            }
        ]
    }
    mock_proc = MagicMock()
    mock_proc.stdout = json.dumps(audit_data)
    mock_proc.returncode = 1

    patch_target = "pyhealth.analyzers.dependencies.subprocess.run"
    with patch(patch_target, return_value=mock_proc):
        issues, count = DependencyAnalyzer(tmp_path)._run_pip_audit({"pkg": "1"})

    assert count == 1
    assert issues[0].code == "PYH203"


# ---------------------------------------------------------------------------
# 21. Missing pip-audit executable handled safely
# ---------------------------------------------------------------------------


def test_missing_pip_audit_handled_safely(tmp_path: Path) -> None:
    """Missing pip-audit executable does not crash analysis."""
    with patch(
        "pyhealth.analyzers.dependencies.subprocess.run",
        side_effect=FileNotFoundError("pip-audit not found"),
    ):
        issues, count = DependencyAnalyzer(tmp_path)._run_pip_audit({"pkg": "1"})

    assert issues == []
    assert count == 0


# ---------------------------------------------------------------------------
# 22. Malformed output handled safely
# ---------------------------------------------------------------------------


def test_malformed_pip_audit_json(tmp_path: Path) -> None:
    """Malformed output from pip-audit returns empty list gracefully."""
    mock_proc = MagicMock()
    mock_proc.stdout = "NOT JSON {"
    mock_proc.returncode = 0

    patch_target = "pyhealth.analyzers.dependencies.subprocess.run"
    with patch(patch_target, return_value=mock_proc):
        issues, count = DependencyAnalyzer(tmp_path)._run_pip_audit({"pkg": "1"})

    assert issues == []
    assert count == 0


# ---------------------------------------------------------------------------
# 23. pyhealth deps <tmp-path>
# ---------------------------------------------------------------------------


def test_cli_deps_command(tmp_path: Path) -> None:
    """``pyhealth deps PATH`` executes successfully."""
    (tmp_path / "requirements.txt").write_text("requests\n")
    (tmp_path / "main.py").write_text("import requests\n")

    with patch.object(DependencyAnalyzer, "_run_pip_audit", return_value=([], 0)):
        res = runner.invoke(app, ["deps", str(tmp_path)])

    assert res.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in res.output
    assert "DEPENDENCIES" in res.output
    assert "Dependency analysis completed" in res.output


# ---------------------------------------------------------------------------
# 24. pyhealth scan <tmp-path> includes dependency summary
# ---------------------------------------------------------------------------


def test_cli_scan_command_with_deps(tmp_path: Path) -> None:
    """``pyhealth scan PATH`` includes DEPENDENCIES summary block."""
    (tmp_path / "main.py").write_text("x = 1\n")

    with patch.object(DependencyAnalyzer, "_run_pip_audit", return_value=([], 0)):
        res = runner.invoke(app, ["scan", str(tmp_path)])

    assert res.exit_code == 0
    assert "PROJECT STATISTICS" in res.output
    assert "CODE QUALITY" in res.output
    assert "SECURITY" in res.output
    assert "COMPLEXITY" in res.output
    assert "DEPENDENCIES" in res.output
    assert "Scan completed successfully" in res.output


# ---------------------------------------------------------------------------
# 25. Existing quality command still works
# ---------------------------------------------------------------------------


def test_cli_quality_command_still_works(tmp_path: Path) -> None:
    """``pyhealth quality PATH`` still works as expected."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["quality", str(tmp_path)])

    assert res.exit_code == 0
    assert "CODE QUALITY" in res.output


# ---------------------------------------------------------------------------
# 26. Existing security command still works
# ---------------------------------------------------------------------------


def test_cli_security_command_still_works(tmp_path: Path) -> None:
    """``pyhealth security PATH`` still works as expected."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["security", str(tmp_path)])

    assert res.exit_code == 0
    assert "SECURITY" in res.output


# ---------------------------------------------------------------------------
# 27. Existing complexity command still works
# ---------------------------------------------------------------------------


def test_cli_complexity_command_still_works(tmp_path: Path) -> None:
    """``pyhealth complexity PATH`` still works as expected."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["complexity", str(tmp_path)])

    assert res.exit_code == 0
    assert "COMPLEXITY" in res.output


# ---------------------------------------------------------------------------
# 28. pyhealth version remains unchanged
# ---------------------------------------------------------------------------


def test_version_remains_2_0_0() -> None:
    """Version command displays PyHealth Scanner 2.0.0."""
    res = runner.invoke(app, ["version"])

    assert res.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in res.output
