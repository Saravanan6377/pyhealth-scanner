"""Release Readiness & Packaging Test Suite for PyHealth Scanner 2.0.0."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pyhealth
from pyhealth.cli import app


def test_package_version_consistency() -> None:
    """Verify pyhealth.__version__ is 2.0.0."""
    assert pyhealth.__version__ == "2.0.0"


def test_pyproject_metadata_presence() -> None:
    """Verify pyproject.toml exists and contains required metadata."""
    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
    assert pyproject_path.is_file()
    content = pyproject_path.read_text(encoding="utf-8")
    # Distribution name must be pyhealth-scanner
    assert 'name = "pyhealth-scanner"' in content
    assert 'version = "2.0.0"' in content
    # CLI entry point installs the pyhealth command
    assert 'pyhealth = "pyhealth.cli:app"' in content
    # License string (SPDX identifier form)
    assert 'license = "MIT"' in content
    assert "typer" in content
    assert "rich" in content
    assert "jinja2" in content


def test_required_documentation_files_exist() -> None:
    """Verify README.md, LICENSE, CHANGELOG.md, and CONTRIBUTING.md exist."""
    root = Path(__file__).parent.parent
    readme = root / "README.md"
    license_file = root / "LICENSE"
    changelog = root / "CHANGELOG.md"
    contributing = root / "CONTRIBUTING.md"

    assert readme.is_file()
    assert license_file.is_file()
    assert changelog.is_file()
    assert contributing.is_file()

    assert len(readme.read_text(encoding="utf-8")) > 100
    assert len(license_file.read_text(encoding="utf-8")) > 100
    assert "2.0.0" in changelog.read_text(encoding="utf-8")
    assert len(contributing.read_text(encoding="utf-8")) > 100


def test_cli_subcommands_registration() -> None:
    """Verify all expected CLI subcommands are registered in Typer app."""
    subcommand_names = [
        cmd.name or (cmd.callback.__name__ if cmd.callback else None)
        for cmd in app.registered_commands
    ]
    expected = [
        "scan",
        "quality",
        "security",
        "complexity",
        "deps",
        "docs",
        "git",
        "report",
        "version",
    ]
    for exp in expected:
        assert exp in subcommand_names


def test_wheel_contents_verification() -> None:
    """Verify generated wheel contains source modules and excludes caches/tests."""
    dist_dir = Path(__file__).parent.parent / "dist"
    wheels = list(dist_dir.glob("*.whl"))
    if not wheels:
        return

    wheel_path = wheels[0]
    with zipfile.ZipFile(wheel_path, "r") as zip_ref:
        names = zip_ref.namelist()
        assert any(n.startswith("pyhealth/__init__.py") for n in names)
        assert any(n.startswith("pyhealth/cli.py") for n in names)
        assert any(n.startswith("pyhealth/reports/html.py") for n in names)

        # Exclusions check
        assert not any(".pytest_cache" in n for n in names)
        assert not any(".ruff_cache" in n for n in names)
        assert not any("__pycache__" in n for n in names)
        assert not any(n.startswith("tests/") for n in names)

        # Check for accidental raw credentials in wheel files
        for name in names:
            if name.endswith((".py", ".json", ".md", ".txt", ".html")):
                content = zip_ref.read(name).decode("utf-8", errors="ignore")
                assert "RAW_UNREDACTED_PASSWORD_123" not in content
                assert "PRIVATE_KEY_REAL_SECRET_TOKEN" not in content


def test_report_template_inclusion() -> None:
    """Verify HtmlReporter template string renders self-contained HTML."""
    from pyhealth.models import ProjectReport
    from pyhealth.reports.html import HtmlReporter

    report = ProjectReport(project_path=Path("."))
    html_output = HtmlReporter().render(report)
    assert "<!DOCTYPE html>" in html_output
    assert "<style>" in html_output
    assert "http://" not in html_output
    assert "https://" not in html_output
