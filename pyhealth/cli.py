"""CLI entry point for PyHealth Scanner.

Provides the ``pyhealth`` command and its sub-commands.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

import pyhealth
from pyhealth.models import (
    ComplexityResult,
    DependencyResult,
    DocumentationResult,
    GitResult,
    HealthReport,
    QualityResult,
    ScanResult,
    SecurityResult,
    Severity,
)
from pyhealth.scanner import ProjectScanner

# Ensure Unicode output (emoji, box-drawing chars) renders correctly on
# Windows terminals that default to the CP1252 code page.
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

app = typer.Typer(
    name="pyhealth",
    help=(
        "🩺 PyHealth Scanner — A unified Python project health analyzer.\n\n"
        "Analyze code quality, security, dependencies, documentation, "
        "complexity, and more in a single command."
    ),
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

_SEPARATOR = "─" * 28

_SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟠",
    Severity.LOW: "🟡",
    Severity.INFO: "ℹ️",
}


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _format_size(size_bytes: int) -> str:
    """Return a human-readable size string (e.g. ``14.2 MB``)."""
    value: float = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


def _print_results(result: ScanResult) -> None:
    """Render the project scan result table to the console."""
    console.print("PROJECT STATISTICS")
    console.print(_SEPARATOR)
    console.print(f"{'Files':<20}{result.total_files:>8}")
    console.print(f"{'Python files':<20}{result.python_files:>8}")
    console.print(f"{'Directories':<20}{result.directories:>8}")
    console.print(f"{'Lines of code':<20}{result.total_lines:>8}")
    console.print(
        f"{'Project size':<20}{_format_size(result.total_size_bytes):>8}"
    )
    console.print()
    console.print("PROJECT STRUCTURE")
    console.print(_SEPARATOR)
    console.print(f"{'Large files':<20}{len(result.large_files):>8}")
    console.print(
        f"{'Empty directories':<20}{len(result.empty_directories):>8}"
    )
    console.print(
        f"{'Duplicate groups':<20}{len(result.duplicate_files):>8}"
    )


def _print_quality_result(result: QualityResult) -> None:
    """Render the full quality report for the ``quality`` command."""
    sev = result.severity_counts

    console.print("CODE QUALITY")
    console.print(_SEPARATOR)
    console.print()
    console.print(f"{'Python files':<22}{result.python_files:>6}")
    console.print(f"{'Total issues':<22}{result.total_issues:>6}")
    console.print()
    console.print(f"{'Ruff findings':<22}{result.ruff_findings:>6}")
    console.print(f"{'Long functions':<22}{result.long_functions:>6}")
    console.print(f"{'Deep nesting':<22}{result.deep_nesting:>6}")
    console.print(f"{'TODO/FIXME':<22}{result.todo_fixme_count:>6}")
    console.print(f"{'Duplicate functions':<22}{result.duplicate_function_count:>6}")
    console.print()
    console.print("SEVERITY")
    console.print(_SEPARATOR)
    console.print()
    for severity in Severity:
        label = severity.value.capitalize()
        console.print(f"{label:<22}{sev[severity]:>6}")


def _print_quality_summary(result: QualityResult) -> None:
    """Render the concise quality section appended to ``scan`` output."""
    console.print()
    console.print("CODE QUALITY")
    console.print(_SEPARATOR)
    console.print(f"{'Python files':<20}{result.python_files:>8}")
    console.print(f"{'Total issues':<20}{result.total_issues:>8}")
    console.print(f"{'Ruff findings':<20}{result.ruff_findings:>8}")
    console.print(f"{'Long functions':<20}{result.long_functions:>8}")
    console.print(f"{'Deep nesting':<20}{result.deep_nesting:>8}")
    console.print(f"{'TODO/FIXME':<20}{result.todo_fixme_count:>8}")
    console.print(
        f"{'Duplicate functions':<20}{result.duplicate_function_count:>8}"
    )


def _print_security_result(result: SecurityResult) -> None:
    """Render the full security report for the ``security`` command."""
    sev = result.severity_counts

    console.print("SECURITY")
    console.print(_SEPARATOR)
    console.print()
    console.print(f"{'Python files analyzed':<24}{result.python_files:>6}")
    console.print(f"{'Total findings':<24}{result.total_findings:>6}")
    console.print()
    console.print(f"{'Bandit findings':<24}{result.bandit_findings:>6}")
    console.print(f"{'Secret findings':<24}{result.secret_findings:>6}")
    console.print()
    console.print("SEVERITY")
    console.print(_SEPARATOR)
    console.print()
    for severity in Severity:
        label = severity.value.capitalize()
        console.print(f"{label:<24}{sev[severity]:>6}")

    if result.issues:
        console.print()
        console.print("ISSUES")
        console.print(_SEPARATOR)
        console.print()
        for issue in result.issues:
            icon = _SEVERITY_ICONS.get(issue.severity, "⚠️")
            console.print(f"{icon} {issue.severity.value.upper()}")
            loc = issue.file or "unknown"
            if issue.line:
                loc += f":{issue.line}"
            console.print(loc)
            console.print(issue.message)
            console.print()


def _print_security_summary(result: SecurityResult) -> None:
    """Render the concise security section appended to ``scan`` output."""
    sev = result.severity_counts
    console.print()
    console.print("SECURITY")
    console.print(_SEPARATOR)
    console.print(f"{'Findings':<20}{result.total_findings:>8}")
    console.print(f"{'High':<20}{sev[Severity.HIGH]:>8}")
    console.print(f"{'Medium':<20}{sev[Severity.MEDIUM]:>8}")
    console.print(f"{'Low':<20}{sev[Severity.LOW]:>8}")


def _print_complexity_result(result: ComplexityResult) -> None:
    """Render the full complexity report for the ``complexity`` command."""
    sev = result.severity_counts
    mi_str = f"{int(round(result.maintainability_index))}/100"

    console.print("COMPLEXITY")
    console.print(_SEPARATOR)
    console.print()
    console.print(f"{'Python files analyzed':<26}{result.python_files:>6}")
    console.print(f"{'Functions analyzed':<26}{result.functions_analyzed:>6}")
    console.print(f"{'Classes analyzed':<26}{result.classes_analyzed:>6}")
    console.print()
    console.print(f"{'Maintainability Index':<26}{mi_str:>6}")
    console.print(f"{'Average Complexity':<26}{result.average_complexity:>6.1f}")
    console.print(f"{'Maximum Complexity':<26}{result.max_complexity:>6}")
    console.print()
    label_high = "High Complexity Findings"
    console.print(f"{label_high:<26}{result.high_complexity_findings:>6}")
    console.print()
    console.print("SEVERITY")
    console.print(_SEPARATOR)
    console.print()
    for severity in Severity:
        label = severity.value.capitalize()
        console.print(f"{label:<26}{sev[severity]:>6}")

    if result.issues:
        console.print()
        console.print("ISSUES")
        console.print(_SEPARATOR)
        console.print()
        for issue in result.issues:
            icon = _SEVERITY_ICONS.get(issue.severity, "⚠️")
            console.print(f"{icon} {issue.severity.value.upper()}")
            loc = issue.file or "unknown"
            if issue.line:
                loc += f":{issue.line}"
            console.print(loc)
            console.print(issue.message)
            console.print()


def _print_complexity_summary(result: ComplexityResult) -> None:
    """Render the concise complexity section appended to ``scan`` output."""
    mi_str = f"{int(round(result.maintainability_index))}/100"
    console.print()
    console.print("COMPLEXITY")
    console.print(_SEPARATOR)
    console.print(f"{'Maintainability':<20}{mi_str:>8}")
    console.print(f"{'Average complexity':<20}{result.average_complexity:>8.1f}")
    console.print(f"{'Maximum complexity':<20}{result.max_complexity:>8}")
    console.print(f"{'High complexity':<20}{result.high_complexity_findings:>8}")


def _print_dependency_result(result: DependencyResult) -> None:
    """Render the full dependency report for the ``deps`` command."""
    console.print("DEPENDENCIES")
    console.print(_SEPARATOR)
    console.print()
    console.print(
        f"{'Declared dependencies':<26}"
        f"{len(result.declared_dependencies):>6}"
    )
    console.print(
        f"{'Imported third-party':<26}"
        f"{len(result.imported_packages):>6}"
    )
    console.print(
        f"{'Installed':<26}"
        f"{len(result.installed_packages):>6}"
    )
    console.print(
        f"{'Potentially unused':<26}"
        f"{len(result.potentially_unused):>6}"
    )
    console.print(
        f"{'Potentially missing':<26}"
        f"{len(result.potentially_missing):>6}"
    )
    console.print(
        f"{'Vulnerabilities':<26}"
        f"{result.vulnerabilities_count:>6}"
    )

    if result.potentially_unused:
        console.print()
        console.print("POTENTIALLY UNUSED")
        console.print(_SEPARATOR)
        console.print()
        for pkg in result.potentially_unused:
            console.print(f"🟡 {pkg}")
            console.print(
                "Verify whether it is required indirectly or dynamically."
            )
            console.print()

    if result.potentially_missing:
        console.print()
        console.print("POTENTIALLY MISSING")
        console.print(_SEPARATOR)
        console.print()
        for issue in result.issues:
            if issue.code == "PYH202":
                pkg = issue.message.split(": ")[-1]
                console.print(f"🟠 {pkg}")
                if issue.file:
                    console.print(f"Imported by: {issue.file}")
                console.print()


def _print_dependency_summary(result: DependencyResult) -> None:
    """Render the concise dependency section appended to ``scan`` output."""
    console.print()
    console.print("DEPENDENCIES")
    console.print(_SEPARATOR)
    console.print(
        f"{'Declared':<20}"
        f"{len(result.declared_dependencies):>8}"
    )
    console.print(
        f"{'Imported':<20}"
        f"{len(result.imported_packages):>8}"
    )
    console.print(
        f"{'Potentially unused':<20}"
        f"{len(result.potentially_unused):>8}"
    )
    console.print(
        f"{'Potentially missing':<20}"
        f"{len(result.potentially_missing):>8}"
    )
    console.print(
        f"{'Vulnerabilities':<20}"
        f"{result.vulnerabilities_count:>8}"
    )


def _print_documentation_result(result: DocumentationResult) -> None:
    """Render the full documentation report for the ``docs`` command."""
    console.print("DOCUMENTATION")
    console.print(_SEPARATOR)
    console.print()
    console.print(f"{'README':<20}{'✓' if result.readme_exists else '✗':>8}")
    console.print(f"{'LICENSE':<20}{'✓' if result.license_exists else '✗':>8}")
    console.print(f"{'CHANGELOG':<20}{'✓' if result.changelog_exists else '✗':>8}")
    contributing_mark = "✓" if result.contributing_exists else "✗"
    console.print(f"{'CONTRIBUTING':<20}{contributing_mark:>8}")
    console.print()
    console.print(f"{'Python files analyzed':<24}{result.files_analyzed:>4}")
    console.print(f"{'Public modules':<24}{result.public_modules:>4}")
    console.print(f"{'Public classes':<24}{result.public_classes:>4}")
    console.print(f"{'Public functions':<24}{result.public_functions:>4}")
    console.print()
    console.print(f"{'Documented objects':<24}{result.documented_objects:>4}")
    coverage_str = f"{int(round(result.docstring_coverage))}%"
    console.print(f"{'Docstring coverage':<24}{coverage_str:>4}")

    if result.issues:
        console.print()
        console.print("ISSUES")
        console.print(_SEPARATOR)
        console.print()
        for issue in result.issues:
            icon = _SEVERITY_ICONS.get(issue.severity, "ℹ️")
            console.print(f"{icon} {issue.severity.value.upper()}")
            if issue.file:
                loc = f"{issue.file}:{issue.line}" if issue.line else issue.file
                console.print(loc)
            console.print(f"{issue.code} — {issue.message}")
            console.print()


def _print_documentation_summary(result: DocumentationResult) -> None:
    """Render the concise documentation section appended to ``scan`` output."""
    console.print()
    console.print("DOCUMENTATION")
    console.print(_SEPARATOR)
    console.print()
    console.print(f"{'README':<20}{'✓' if result.readme_exists else '✗':>8}")
    console.print(f"{'LICENSE':<20}{'✓' if result.license_exists else '✗':>8}")
    console.print(f"{'CHANGELOG':<20}{'✓' if result.changelog_exists else '✗':>8}")
    contributing_mark = "✓" if result.contributing_exists else "✗"
    console.print(f"{'CONTRIBUTING':<20}{contributing_mark:>8}")
    console.print()
    coverage_str = f"{int(round(result.docstring_coverage))}%"
    console.print(f"{'Docstring coverage':<20}{coverage_str:>8}")
    console.print(f"{'Issues':<20}{result.total_findings:>8}")


def _print_git_result(result: GitResult) -> None:
    """Render the full Git health report for the ``git`` command."""
    console.print("GIT HEALTH")
    console.print(_SEPARATOR)
    console.print()
    console.print(
        f"{'Repository':<20}{'✓' if result.repository_detected else '✗':>8}"
    )
    console.print(f"{'.gitignore':<20}{'✓' if result.gitignore_exists else '✗':>8}")
    console.print()
    if result.repository_detected:
        console.print(f"{'Tracked files':<20}{result.tracked_files_count:>8}")
        console.print(f"{'Untracked files':<20}{result.untracked_files_count:>8}")
        commits_str = (
            str(result.commit_count) if result.commit_count is not None else "N/A"
        )
        console.print(f"{'Commits':<20}{commits_str:>8}")
        branch_str = result.branch_name if result.branch_name else "N/A"
        console.print(f"{'Branch':<20}{branch_str:>8}")
        console.print()
        console.print(
            f"{'Large tracked files':<20}{len(result.large_tracked_files):>8}"
        )
        console.print(
            f"{'Sensitive tracked':<20}{len(result.sensitive_tracked_files):>8}"
        )

    if result.issues:
        console.print()
        console.print("ISSUES")
        console.print(_SEPARATOR)
        console.print()
        for issue in result.issues:
            icon = _SEVERITY_ICONS.get(issue.severity, "ℹ️")
            console.print(f"{icon} {issue.severity.value.upper()}")
            if issue.file:
                console.print(f"{issue.file}")
            console.print(f"{issue.code} — {issue.message}")
            console.print()


def _print_git_summary(result: GitResult) -> None:
    """Render the concise Git health section appended to ``scan`` output."""
    console.print()
    console.print("GIT HEALTH")
    console.print(_SEPARATOR)
    console.print()
    console.print(
        f"{'Repository':<20}{'✓' if result.repository_detected else '✗':>8}"
    )
    console.print(f"{'.gitignore':<20}{'✓' if result.gitignore_exists else '✗':>8}")
    if result.repository_detected:
        console.print(f"{'Tracked files':<20}{result.tracked_files_count:>8}")
        console.print(f"{'Untracked files':<20}{result.untracked_files_count:>8}")
        console.print(
            f"{'Large tracked':<20}{len(result.large_tracked_files):>8}"
        )
        console.print(
            f"{'Sensitive tracked':<20}{len(result.sensitive_tracked_files):>8}"
        )
    console.print(f"{'Issues':<20}{result.total_findings:>8}")


def _print_health_summary(report: HealthReport) -> None:
    """Render the overall health score and top priorities at the end of scan."""
    console.print()
    console.print("HEALTH SCORE")
    console.print(_SEPARATOR)
    console.print()
    console.print(f"{'Overall':<20}{f'{int(round(report.overall_score))}/100':>8}")
    console.print(f"{'Grade':<20}{report.grade:>8}")
    console.print()

    for cat in report.categories:
        label = cat.name.capitalize()
        if cat.available:
            score_str = f"{int(round(cat.score))}/100"
        else:
            score_str = "N/A"
        console.print(f"{label:<20}{score_str:>8}")

    if report.recommendations:
        console.print()
        console.print("TOP PRIORITIES")
        console.print(_SEPARATOR)
        console.print()
        for idx, rec in enumerate(report.recommendations, start=1):
            console.print(f"{idx}. {rec}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Display the current PyHealth Scanner version."""
    console.print(f"PyHealth Scanner {pyhealth.__version__}", highlight=False)


@app.command()
def scan(
    path: str = typer.Argument(
        default=".",
        help="Path to the project directory to scan.",
        show_default=True,
    ),
) -> None:
    """Scan a project directory and report its health."""
    console.print(
        f"\n🩺 PyHealth Scanner {pyhealth.__version__}\n", highlight=False
    )
    console.print(f"Scanning: {path}\n")

    scanner = ProjectScanner()
    try:
        scan_result = scanner.scan(Path(path))
    except FileNotFoundError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except NotADirectoryError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc

    _print_results(scan_result)

    # Code quality summary
    from pyhealth.analyzers.quality import QualityAnalyzer  # noqa: PLC0415

    quality_result = QualityAnalyzer(Path(path)).analyze()
    _print_quality_summary(quality_result)

    # Security summary
    from pyhealth.analyzers.security import SecurityAnalyzer  # noqa: PLC0415

    security_result = SecurityAnalyzer(Path(path)).analyze()
    _print_security_summary(security_result)

    # Complexity summary
    from pyhealth.analyzers.complexity import ComplexityAnalyzer  # noqa: PLC0415

    complexity_result = ComplexityAnalyzer(Path(path)).analyze()
    _print_complexity_summary(complexity_result)

    # Dependency summary
    from pyhealth.analyzers.dependencies import DependencyAnalyzer  # noqa: PLC0415

    dependency_result = DependencyAnalyzer(Path(path)).analyze()
    _print_dependency_summary(dependency_result)

    # Documentation summary
    from pyhealth.analyzers.documentation import DocumentationAnalyzer  # noqa: PLC0415

    documentation_result = DocumentationAnalyzer(Path(path)).analyze()
    _print_documentation_summary(documentation_result)

    # Git summary
    from pyhealth.analyzers.git import GitAnalyzer  # noqa: PLC0415

    git_result = GitAnalyzer(Path(path)).analyze()
    _print_git_summary(git_result)

    # Unified Health Score Engine calculation
    from pyhealth.health import HealthScoreEngine  # noqa: PLC0415

    engine = HealthScoreEngine(
        quality=quality_result,
        security=security_result,
        complexity=complexity_result,
        dependencies=dependency_result,
        documentation=documentation_result,
        structure=scan_result,
        git=git_result,
        config_path=Path(path) / "pyproject.toml",
    )
    health_report = engine.calculate()
    _print_health_summary(health_report)

    console.print("\n✓ Scan completed successfully.")


@app.command()
def report(
    path: str = typer.Argument(
        default=".",
        help="Path to the project directory to report on.",
        show_default=True,
    ),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Report format (console, json, markdown, html, csv, sarif, all).",
        show_default=True,
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path or directory (for format 'all').",
        show_default=False,
    ),
) -> None:
    """Generate a project health report in various formats."""
    from pyhealth.reports import (
        VALID_FORMATS,
        create_project_report,
        get_reporter,
    )

    fmt_lower = format.lower().strip()
    if fmt_lower not in VALID_FORMATS:
        fmt_list = ", ".join(sorted(VALID_FORMATS))
        console.print(
            f"Error: Invalid format '{format}'. Allowed formats: {fmt_list}"
        )
        raise typer.Exit(code=1)

    project_path = Path(path)
    if not project_path.exists():
        console.print(f"Error: Path '{path}' does not exist.")
        raise typer.Exit(code=1)

    if fmt_lower == "console" and output is None:
        scan(path=path)
        return

    # Execute analysis EXACTLY ONCE into ProjectReport
    try:
        project_report = create_project_report(project_path)
    except FileNotFoundError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except NotADirectoryError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc

    if fmt_lower == "console":
        rep = get_reporter("markdown")
        content = rep.render(project_report)
        out_file = Path(output)  # type: ignore[arg-type]
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content, encoding="utf-8")
        console.print(f"✓ Report saved to {out_file}")
        return

    if fmt_lower == "all":
        out_dir = Path(output) if output else Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)

        formats_to_ext = {
            "json": "report.json",
            "markdown": "report.md",
            "html": "report.html",
            "csv": "report.csv",
            "sarif": "report.sarif",
        }

        generated_files: list[Path] = []
        for fmt_key, filename in formats_to_ext.items():
            rep = get_reporter(fmt_key)
            rendered = rep.render(project_report)
            file_path = out_dir / filename
            file_path.write_text(rendered, encoding="utf-8")
            generated_files.append(file_path)

        console.print("✓ Reports generated successfully:")
        for gf in generated_files:
            console.print(f"  - {gf}")
        return

    # Single format rendering
    rep = get_reporter(fmt_lower)
    content = rep.render(project_report)

    if output:
        out_file = Path(output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content, encoding="utf-8")
        console.print(f"✓ Report saved to {out_file}")
    elif fmt_lower == "html":
        out_file = Path("report.html")
        out_file.write_text(content, encoding="utf-8")
        console.print(f"✓ Report saved to {out_file}")
    else:
        # Print text formats (json, markdown, csv, sarif) to stdout
        print(content)


@app.command()
def quality(
    path: str = typer.Argument(
        default=".",
        help="Path to the project directory to analyse.",
        show_default=True,
    ),
) -> None:
    """Analyse code quality of a project directory."""
    from pyhealth.analyzers.quality import QualityAnalyzer  # noqa: PLC0415

    console.print(
        f"\n🩺 PyHealth Scanner {pyhealth.__version__}\n", highlight=False
    )
    console.print(f"Analyzing code quality:\n{path}\n")

    try:
        result = QualityAnalyzer(Path(path)).analyze()
    except FileNotFoundError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except NotADirectoryError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc

    _print_quality_result(result)
    console.print("\n✓ Quality analysis completed.")


@app.command()
def security(
    path: str = typer.Argument(
        default=".",
        help="Path to the project directory to analyse.",
        show_default=True,
    ),
) -> None:
    """Analyse security of a project directory."""
    from pyhealth.analyzers.security import SecurityAnalyzer  # noqa: PLC0415

    console.print(
        f"\n🩺 PyHealth Scanner {pyhealth.__version__}\n", highlight=False
    )
    console.print(f"Analyzing security:\n{path}\n")

    try:
        result = SecurityAnalyzer(Path(path)).analyze()
    except FileNotFoundError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except NotADirectoryError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc

    _print_security_result(result)
    console.print("\n✓ Security analysis completed.")


@app.command()
def complexity(
    path: str = typer.Argument(
        default=".",
        help="Path to the project directory to analyse.",
        show_default=True,
    ),
) -> None:
    """Analyse code complexity of a project directory."""
    from pyhealth.analyzers.complexity import ComplexityAnalyzer  # noqa: PLC0415

    console.print(
        f"\n🩺 PyHealth Scanner {pyhealth.__version__}\n", highlight=False
    )
    console.print(f"Analyzing complexity:\n{path}\n")

    try:
        result = ComplexityAnalyzer(Path(path)).analyze()
    except FileNotFoundError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except NotADirectoryError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc

    _print_complexity_result(result)
    console.print("\n✓ Complexity analysis completed.")


@app.command()
def deps(
    path: str = typer.Argument(
        default=".",
        help="Path to the project directory to analyse.",
        show_default=True,
    ),
) -> None:
    """Analyse dependencies of a project directory."""
    from pyhealth.analyzers.dependencies import DependencyAnalyzer  # noqa: PLC0415

    console.print(
        f"\n🩺 PyHealth Scanner {pyhealth.__version__}\n", highlight=False
    )
    console.print(f"Analyzing dependencies:\n{path}\n")

    try:
        result = DependencyAnalyzer(Path(path)).analyze()
    except FileNotFoundError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except NotADirectoryError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc

    _print_dependency_result(result)
    console.print("\n✓ Dependency analysis completed.")


@app.command()
def docs(
    path: str = typer.Argument(
        default=".",
        help="Path to the project directory to analyse.",
        show_default=True,
    ),
) -> None:
    """Analyse documentation quality and docstring coverage of a project directory."""
    from pyhealth.analyzers.documentation import DocumentationAnalyzer  # noqa: PLC0415

    console.print(
        f"\n🩺 PyHealth Scanner {pyhealth.__version__}\n", highlight=False
    )
    console.print(f"Analyzing documentation:\n{path}\n")

    try:
        result = DocumentationAnalyzer(Path(path)).analyze()
    except FileNotFoundError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except NotADirectoryError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc

    _print_documentation_result(result)
    console.print("\n✓ Documentation analysis completed.")


@app.command()
def git(
    path: str = typer.Argument(
        default=".",
        help="Path to the project directory to analyse.",
        show_default=True,
    ),
) -> None:
    """Analyse Git health and repository security hygiene of a project directory."""
    from pyhealth.analyzers.git import GitAnalyzer  # noqa: PLC0415

    console.print(
        f"\n🩺 PyHealth Scanner {pyhealth.__version__}\n", highlight=False
    )
    console.print(f"Analyzing Git health:\n{path}\n")

    try:
        result = GitAnalyzer(Path(path)).analyze()
    except FileNotFoundError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except NotADirectoryError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        console.print(f"Error: {exc}")
        raise typer.Exit(code=1) from exc

    _print_git_result(result)
    console.print("\n✓ Git analysis completed.")
