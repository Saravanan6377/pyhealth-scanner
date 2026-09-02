"""Tests for the PyHealth package foundation (Stage 1)."""

from __future__ import annotations

from typer.testing import CliRunner

import pyhealth
from pyhealth.cli import app

runner = CliRunner()


def test_package_version() -> None:
    """Package version must be exactly 2.0.0."""
    assert pyhealth.__version__ == "2.0.0"


def test_version_command() -> None:
    """``pyhealth version`` should print the version string and exit cleanly."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "2.0.0" in result.output


def test_scan_command_exit_code() -> None:
    """``pyhealth scan .`` should return exit code 0."""
    result = runner.invoke(app, ["scan", "."])
    assert result.exit_code == 0


def test_scan_command_output() -> None:
    """``pyhealth scan .`` displays the banner, stats table, and success marker."""
    result = runner.invoke(app, ["scan", "."])
    assert result.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in result.output
    assert "Scanning: ." in result.output
    assert "Scan completed successfully" in result.output
