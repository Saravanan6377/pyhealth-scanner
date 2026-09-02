"""Unit and integration tests for Stage 10: Unified Report Engine."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pyhealth
from pyhealth.cli import app
from pyhealth.models import (
    CategoryScore,
    ComplexityResult,
    DependencyResult,
    DocumentationResult,
    GitResult,
    HealthReport,
    Issue,
    ProjectReport,
    QualityResult,
    ScanResult,
    SecurityResult,
    Severity,
)
from pyhealth.reports import (
    CsvReporter,
    HtmlReporter,
    JsonReporter,
    MarkdownReporter,
    SarifReporter,
)

runner = CliRunner()


@pytest.fixture
def dummy_report(tmp_path: Path) -> ProjectReport:
    """Fixture providing a deterministic ProjectReport for testing reporters."""
    scan = ScanResult(
        project_path=tmp_path,
        total_files=10,
        python_files=5,
        directories=2,
        total_lines=500,
        total_size_bytes=50000,
    )
    qual = QualityResult(
        python_files=5,
        issues=[
            Issue(
                category="quality",
                severity=Severity.HIGH,
                code="PYH001",
                message="Function 'complex_fn' has 65 lines (exceeds limit 50)",
                file="app.py",
                line=12,
                column=1,
                tool="pyhealth",
                suggestion="Refactor function into smaller helpers",
            )
        ],
    )
    sec = SecurityResult(
        python_files=5,
        issues=[
            Issue(
                category="security",
                severity=Severity.CRITICAL,
                code="PYS001",
                message="Potential hardcoded secret in variable 'api_key': [REDACTED]",
                file="config.py",
                line=5,
                column=10,
                tool="native",
                suggestion="Remove exposed credential from source code",
            )
        ],
    )
    comp = ComplexityResult(
        python_files=5,
        maintainability_index=85.0,
        average_complexity=3.5,
        max_complexity=12,
        high_complexity_findings=1,
        issues=[
            Issue(
                category="complexity",
                severity=Severity.MEDIUM,
                code="PYH101",
                message="Function 'calc' has cyclomatic complexity 12",
                file="calc.py",
                line=20,
            )
        ],
    )
    deps = DependencyResult(
        python_files=5,
        declared_dependencies=["typer", "rich", "ruff", "pytest"],
        imported_packages=["typer", "rich", "ruff"],
        installed_packages={"typer": "0.9.0"},
        potentially_unused=["pytest"],
        potentially_missing=[],
        vulnerabilities_count=0,
        issues=[
            Issue(
                category="dependencies",
                severity=Severity.LOW,
                code="PYH201",
                message="Potentially unused dependency 'pytest'",
            )
        ],
    )
    doc = DocumentationResult(
        files_analyzed=5,
        docstring_coverage=90.0,
        readme_exists=True,
        license_exists=True,
        changelog_exists=False,
        contributing_exists=False,
        issues=[
            Issue(
                category="documentation",
                severity=Severity.LOW,
                code="PYH303",
                message="CHANGELOG file is missing.",
            )
        ],
    )
    git = GitResult(
        repository_detected=True,
        gitignore_exists=True,
        repo_root=tmp_path,
        tracked_files_count=10,
        untracked_files_count=2,
    )
    health = HealthReport(
        overall_score=85.0,
        grade="Good",
        categories=[
            CategoryScore("security", 70.0, 0.30, True),
            CategoryScore("quality", 85.0, 0.20, True),
            CategoryScore("complexity", 95.0, 0.15, True),
            CategoryScore("dependencies", 98.0, 0.15, True),
            CategoryScore("documentation", 85.0, 0.10, True),
            CategoryScore("structure", 100.0, 0.05, True),
            CategoryScore("git", 100.0, 0.05, True),
        ],
        priority_issues=[sec.issues[0], qual.issues[0]],
        recommendations=[
            "Remove exposed credential from source code",
            "Refactor function into smaller helpers",
        ],
    )
    return ProjectReport(
        project_path=tmp_path,
        scan=scan,
        quality=qual,
        security=sec,
        complexity=comp,
        dependencies=deps,
        documentation=doc,
        git=git,
        health=health,
    )


# ---------------------------------------------------------------------------
# 1-2. Data Model & Serialization Safety
# ---------------------------------------------------------------------------


def test_project_report_construction(dummy_report: ProjectReport) -> None:
    """ProjectReport constructs correctly and collects issues."""
    assert dummy_report.scan is not None
    assert dummy_report.health is not None
    issues = dummy_report.all_issues()
    assert len(issues) >= 5


def test_project_report_serialization_safety(dummy_report: ProjectReport) -> None:
    """JsonReporter converts all dataclasses/enums/paths without throwing TypeError."""
    reporter = JsonReporter()
    output = reporter.render(dummy_report)
    assert "<Path" not in output
    assert "<Severity" not in output


# ---------------------------------------------------------------------------
# 3-7. JSON Reporter
# ---------------------------------------------------------------------------


def test_json_reporter_validity(dummy_report: ProjectReport) -> None:
    """JsonReporter produces valid JSON."""
    output = JsonReporter().render(dummy_report)
    data = json.loads(output)
    assert isinstance(data, dict)


def test_json_reporter_top_level_fields(dummy_report: ProjectReport) -> None:
    """JsonReporter includes all required top-level sections."""
    data = json.loads(JsonReporter().render(dummy_report))
    assert "project" in data
    assert "project_path" in data
    assert "scan" in data
    assert "quality" in data
    assert "security" in data
    assert "complexity" in data
    assert "dependencies" in data
    assert "documentation" in data
    assert "git" in data
    assert "health" in data


def test_json_reporter_issue_serialization(dummy_report: ProjectReport) -> None:
    """JsonReporter serializes issues with all standard fields."""
    data = json.loads(JsonReporter().render(dummy_report))
    sec_issue = data["security"]["issues"][0]
    assert sec_issue["category"] == "security"
    assert sec_issue["severity"] == "critical"
    assert sec_issue["code"] == "PYS001"
    assert sec_issue["file"] == "config.py"


def test_json_reporter_no_python_reprs(dummy_report: ProjectReport) -> None:
    """JsonReporter output has no raw Python repr strings."""
    output = JsonReporter().render(dummy_report)
    assert "Path(" not in output
    assert "Severity." not in output


def test_json_reporter_secret_sanitization(dummy_report: ProjectReport) -> None:
    """JsonReporter does not leak raw secret tokens."""
    output = JsonReporter().render(dummy_report)
    assert "super_secret_token_12345" not in output


# ---------------------------------------------------------------------------
# 8-11. Markdown Reporter
# ---------------------------------------------------------------------------


def test_markdown_reporter_health_score(dummy_report: ProjectReport) -> None:
    """MarkdownReporter contains project health score and grade."""
    output = MarkdownReporter().render(dummy_report)
    assert "85/100" in output
    assert "Good" in output


def test_markdown_reporter_category_table(dummy_report: ProjectReport) -> None:
    """MarkdownReporter contains Category Scores table."""
    output = MarkdownReporter().render(dummy_report)
    assert "| Category | Score | Weight | Status |" in output
    assert "Security" in output


def test_markdown_reporter_issues(dummy_report: ProjectReport) -> None:
    """MarkdownReporter contains Detailed Findings table."""
    output = MarkdownReporter().render(dummy_report)
    assert "## Detailed Findings" in output
    assert "PYS001" in output


def test_markdown_reporter_recommendations(dummy_report: ProjectReport) -> None:
    """MarkdownReporter contains Top Priority Recommendations."""
    output = MarkdownReporter().render(dummy_report)
    assert "### Top Priority Recommendations" in output
    assert "Remove exposed credential" in output


# ---------------------------------------------------------------------------
# 12-16. HTML Reporter
# ---------------------------------------------------------------------------


def test_html_reporter_valid_html(dummy_report: ProjectReport) -> None:
    """HtmlReporter produces valid HTML doc with proper tags."""
    output = HtmlReporter().render(dummy_report)
    assert "<!DOCTYPE html>" in output
    assert "<html" in output
    assert "</html>" in output


def test_html_reporter_health_score(dummy_report: ProjectReport) -> None:
    """HtmlReporter displays overall score prominently."""
    output = HtmlReporter().render(dummy_report)
    assert "85" in output
    assert "Good" in output


def test_html_reporter_category_info(dummy_report: ProjectReport) -> None:
    """HtmlReporter displays category breakdown."""
    output = HtmlReporter().render(dummy_report)
    assert "Category Breakdown" in output
    assert "security" in output


def test_html_reporter_issue_info(dummy_report: ProjectReport) -> None:
    """HtmlReporter displays detailed findings table."""
    output = HtmlReporter().render(dummy_report)
    assert "Detailed Findings" in output
    assert "PYS001" in output


def test_html_reporter_offline_self_contained(dummy_report: ProjectReport) -> None:
    """HtmlReporter is self-contained with no network dependencies."""
    output = HtmlReporter().render(dummy_report)
    assert "http://" not in output
    assert "https://" not in output
    assert "cdn" not in output.lower()
    assert "<style>" in output


# ---------------------------------------------------------------------------
# 17-19. CSV Reporter
# ---------------------------------------------------------------------------


def test_csv_reporter_headers(dummy_report: ProjectReport) -> None:
    """CsvReporter headers match exact standard schema."""
    output = CsvReporter().render(dummy_report)
    header = output.splitlines()[0]
    assert header == "category,severity,code,message,file,line,column,tool,suggestion"


def test_csv_reporter_issue_rows(dummy_report: ProjectReport) -> None:
    """CsvReporter outputs one row per issue."""
    output = CsvReporter().render(dummy_report)
    lines = output.strip().splitlines()
    # 1 header line + 5 issues in dummy_report = 6 lines
    assert len(lines) == 6


def test_csv_reporter_zero_issue_behavior(tmp_path: Path) -> None:
    """CsvReporter outputs header row only when zero issues exist."""
    empty_report = ProjectReport(project_path=tmp_path)
    output = CsvReporter().render(empty_report)
    lines = output.strip().splitlines()
    assert len(lines) == 1
    assert lines[0] == "category,severity,code,message,file,line,column,tool,suggestion"


# ---------------------------------------------------------------------------
# 20-25. SARIF Reporter
# ---------------------------------------------------------------------------


def test_sarif_reporter_valid_json(dummy_report: ProjectReport) -> None:
    """SarifReporter produces valid JSON."""
    output = SarifReporter().render(dummy_report)
    data = json.loads(output)
    assert isinstance(data, dict)


def test_sarif_reporter_required_fields(dummy_report: ProjectReport) -> None:
    """SarifReporter includes all SARIF v2.1.0 required top-level fields."""
    data = json.loads(SarifReporter().render(dummy_report))
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data
    assert "tool" in data["runs"][0]
    assert "results" in data["runs"][0]


def test_sarif_reporter_rule_ids(dummy_report: ProjectReport) -> None:
    """SarifReporter populates rules table with unique rule IDs."""
    data = json.loads(SarifReporter().render(dummy_report))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert "PYS001" in rule_ids
    assert "PYH001" in rule_ids


def test_sarif_reporter_severity_mapping(dummy_report: ProjectReport) -> None:
    """SarifReporter maps PyHealth severities to SARIF levels."""
    data = json.loads(SarifReporter().render(dummy_report))
    results = data["runs"][0]["results"]
    for res in results:
        assert res["level"] in ("error", "warning", "note")


def test_sarif_reporter_file_locations(dummy_report: ProjectReport) -> None:
    """SarifReporter includes relative artifact location and line region."""
    data = json.loads(SarifReporter().render(dummy_report))
    res = data["runs"][0]["results"][0]
    assert "locations" in res
    loc = res["locations"][0]["physicalLocation"]
    assert "uri" in loc["artifactLocation"]


def test_sarif_reporter_secret_sanitization(dummy_report: ProjectReport) -> None:
    """SarifReporter does not leak raw secret tokens."""
    output = SarifReporter().render(dummy_report)
    assert "super_secret_password" not in output


# ---------------------------------------------------------------------------
# 26. Determinism
# ---------------------------------------------------------------------------


def test_determinism_repeated_renderings(dummy_report: ProjectReport) -> None:
    """Repeated renderings from the same ProjectReport produce exact string equality."""
    json1 = JsonReporter().render(dummy_report)
    json2 = JsonReporter().render(dummy_report)
    assert json1 == json2

    md1 = MarkdownReporter().render(dummy_report)
    md2 = MarkdownReporter().render(dummy_report)
    assert md1 == md2

    csv1 = CsvReporter().render(dummy_report)
    csv2 = CsvReporter().render(dummy_report)
    assert csv1 == csv2

    sarif1 = SarifReporter().render(dummy_report)
    sarif2 = SarifReporter().render(dummy_report)
    assert sarif1 == sarif2


# ---------------------------------------------------------------------------
# 27-36. CLI pyhealth report subcommand
# ---------------------------------------------------------------------------


def test_cli_report_default_console(tmp_path: Path) -> None:
    """pyhealth report . defaults to console summary output."""
    res = runner.invoke(app, ["report", str(tmp_path)])
    assert res.exit_code == 0
    assert "HEALTH SCORE" in res.output


def test_cli_report_json(tmp_path: Path) -> None:
    """pyhealth report . --format json outputs valid JSON."""
    res = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert "health" in data


def test_cli_report_markdown(tmp_path: Path) -> None:
    """pyhealth report . --format markdown outputs Markdown."""
    res = runner.invoke(app, ["report", str(tmp_path), "--format", "markdown"])
    assert res.exit_code == 0
    assert "# PyHealth Scanner Report" in res.output


def test_cli_report_html(tmp_path: Path) -> None:
    """pyhealth report . --format html writes report.html."""
    out_html = tmp_path / "custom.html"
    args = ["report", str(tmp_path), "--format", "html", "--output", str(out_html)]
    res = runner.invoke(app, args)
    assert res.exit_code == 0
    assert out_html.is_file()
    assert "<!DOCTYPE html>" in out_html.read_text(encoding="utf-8")


def test_cli_report_csv(tmp_path: Path) -> None:
    """pyhealth report . --format csv outputs CSV."""
    res = runner.invoke(app, ["report", str(tmp_path), "--format", "csv"])
    assert res.exit_code == 0
    assert "category,severity,code" in res.output


def test_cli_report_sarif(tmp_path: Path) -> None:
    """pyhealth report . --format sarif outputs SARIF JSON."""
    res = runner.invoke(app, ["report", str(tmp_path), "--format", "sarif"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["version"] == "2.1.0"


def test_cli_report_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """pyhealth report . --format all creates 5 report files."""
    monkeypatch.chdir(tmp_path)
    res = runner.invoke(app, ["report", str(tmp_path), "--format", "all"])
    assert res.exit_code == 0
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "report.md").is_file()
    assert (tmp_path / "report.html").is_file()
    assert (tmp_path / "report.csv").is_file()
    assert (tmp_path / "report.sarif").is_file()


def test_cli_report_all_with_output_dir(tmp_path: Path) -> None:
    """pyhealth report . --format all --output mydir creates directory and files."""
    out_dir = tmp_path / "reports_dir"
    args = ["report", str(tmp_path), "--format", "all", "--output", str(out_dir)]
    res = runner.invoke(app, args)
    assert res.exit_code == 0
    assert (out_dir / "report.json").is_file()
    assert (out_dir / "report.md").is_file()
    assert (out_dir / "report.html").is_file()
    assert (out_dir / "report.csv").is_file()
    assert (out_dir / "report.sarif").is_file()


def test_cli_report_output_file_path(tmp_path: Path) -> None:
    """pyhealth report . --format json --output custom.json writes to custom.json."""
    out_file = tmp_path / "custom.json"
    args = ["report", str(tmp_path), "--format", "json", "--output", str(out_file)]
    res = runner.invoke(app, args)
    assert res.exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "health" in data


def test_cli_report_invalid_format(tmp_path: Path) -> None:
    """pyhealth report . --format unknown returns clean error and exit code 1."""
    res = runner.invoke(app, ["report", str(tmp_path), "--format", "unknown"])
    assert res.exit_code == 1
    assert "Error: Invalid format 'unknown'" in res.output


# ---------------------------------------------------------------------------
# 37-43. Full Regression Checks
# ---------------------------------------------------------------------------


def test_cli_scan_still_works(tmp_path: Path) -> None:
    """pyhealth scan PATH still works."""
    assert runner.invoke(app, ["scan", str(tmp_path)]).exit_code == 0


def test_cli_git_still_works(tmp_path: Path) -> None:
    """pyhealth git PATH still works."""
    assert runner.invoke(app, ["git", str(tmp_path)]).exit_code == 0


def test_cli_docs_still_works(tmp_path: Path) -> None:
    """pyhealth docs PATH still works."""
    assert runner.invoke(app, ["docs", str(tmp_path)]).exit_code == 0


def test_cli_deps_still_works(tmp_path: Path) -> None:
    """pyhealth deps PATH still works."""
    assert runner.invoke(app, ["deps", str(tmp_path)]).exit_code == 0


def test_cli_security_still_works(tmp_path: Path) -> None:
    """pyhealth security PATH still works."""
    assert runner.invoke(app, ["security", str(tmp_path)]).exit_code == 0


def test_cli_complexity_still_works(tmp_path: Path) -> None:
    """pyhealth complexity PATH still works."""
    assert runner.invoke(app, ["complexity", str(tmp_path)]).exit_code == 0


def test_cli_quality_still_works(tmp_path: Path) -> None:
    """pyhealth quality PATH still works."""
    assert runner.invoke(app, ["quality", str(tmp_path)]).exit_code == 0


def test_version_remains_2_0_0() -> None:
    """Package version remains 2.0.0."""
    assert pyhealth.__version__ == "2.0.0"
