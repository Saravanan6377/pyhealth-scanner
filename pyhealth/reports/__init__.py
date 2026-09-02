"""PyHealth Unified Report Engine package.

Provides reporters for JSON, Markdown, HTML, CSV, and SARIF formats, as well as
single-run execution helpers.
"""

from __future__ import annotations

from pathlib import Path

from pyhealth.analyzers.complexity import ComplexityAnalyzer
from pyhealth.analyzers.dependencies import DependencyAnalyzer
from pyhealth.analyzers.documentation import DocumentationAnalyzer
from pyhealth.analyzers.git import GitAnalyzer
from pyhealth.analyzers.quality import QualityAnalyzer
from pyhealth.analyzers.security import SecurityAnalyzer
from pyhealth.health import HealthScoreEngine
from pyhealth.models import ProjectReport
from pyhealth.reports.base import Reporter
from pyhealth.reports.csv import CsvReporter
from pyhealth.reports.html import HtmlReporter
from pyhealth.reports.json import JsonReporter
from pyhealth.reports.markdown import MarkdownReporter
from pyhealth.reports.sarif import SarifReporter
from pyhealth.scanner import ProjectScanner

VALID_FORMATS: set[str] = {
    "console",
    "json",
    "markdown",
    "html",
    "csv",
    "sarif",
    "all",
}


def get_reporter(fmt: str) -> Reporter:
    """Return a Reporter instance for the given format string.

    Raises:
        ValueError: If fmt is unknown or unsupported.
    """
    fmt_lower = fmt.lower().strip()
    if fmt_lower == "json":
        return JsonReporter()
    if fmt_lower == "markdown" or fmt_lower == "md":
        return MarkdownReporter()
    if fmt_lower == "html":
        return HtmlReporter()
    if fmt_lower == "csv":
        return CsvReporter()
    if fmt_lower == "sarif":
        return SarifReporter()

    raise ValueError(
        f"Invalid format '{fmt}'. Allowed formats: {', '.join(sorted(VALID_FORMATS))}"
    )


def create_project_report(project_path: Path) -> ProjectReport:
    """Run all analyzers ONCE and return a unified ProjectReport."""
    scanner = ProjectScanner()
    scan_res = scanner.scan(project_path)

    qual_res = QualityAnalyzer(project_path).analyze()
    sec_res = SecurityAnalyzer(project_path).analyze()
    comp_res = ComplexityAnalyzer(project_path).analyze()
    dep_res = DependencyAnalyzer(project_path).analyze()
    doc_res = DocumentationAnalyzer(project_path).analyze()
    git_res = GitAnalyzer(project_path).analyze()

    engine = HealthScoreEngine(
        quality=qual_res,
        security=sec_res,
        complexity=comp_res,
        dependencies=dep_res,
        documentation=doc_res,
        structure=scan_res,
        git=git_res,
        config_path=project_path / "pyproject.toml",
    )
    health_rep = engine.calculate()

    return ProjectReport(
        project_path=project_path,
        scan=scan_res,
        quality=qual_res,
        security=sec_res,
        complexity=comp_res,
        dependencies=dep_res,
        documentation=doc_res,
        git=git_res,
        health=health_rep,
    )


__all__ = [
    "Reporter",
    "JsonReporter",
    "MarkdownReporter",
    "HtmlReporter",
    "CsvReporter",
    "SarifReporter",
    "ProjectReport",
    "VALID_FORMATS",
    "get_reporter",
    "create_project_report",
]
