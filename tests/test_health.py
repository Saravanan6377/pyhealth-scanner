"""Tests for Stage 9: Unified Health Score Engine."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

import pyhealth
from pyhealth.cli import app
from pyhealth.health import DEFAULT_CATEGORY_WEIGHTS, HealthScoreEngine
from pyhealth.models import (
    CategoryScore,
    ComplexityResult,
    DependencyResult,
    DocumentationResult,
    GitResult,
    HealthReport,
    Issue,
    QualityResult,
    ScanResult,
    SecurityResult,
    Severity,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1-2. Dataclass construction
# ---------------------------------------------------------------------------


def test_category_score_construction() -> None:
    """CategoryScore dataclass initializes correctly."""
    cs = CategoryScore(name="security", score=90.0, weight=0.30, available=True)
    assert cs.name == "security"
    assert cs.score == 90.0
    assert cs.weight == 0.30
    assert cs.available is True


def test_health_report_construction() -> None:
    """HealthReport dataclass initializes and maps categories correctly."""
    cs = CategoryScore(name="security", score=90.0, weight=0.30)
    report = HealthReport(
        overall_score=90.0,
        grade="Excellent",
        categories=[cs],
        priority_issues=[],
        recommendations=["Fix issues."],
    )
    assert report.overall_score == 90.0
    assert report.grade == "Excellent"
    assert report.category_map["security"].score == 90.0
    assert report.recommendations == ["Fix issues."]


# ---------------------------------------------------------------------------
# 3-6. Weights & Configuration Validation
# ---------------------------------------------------------------------------


def test_default_category_weights() -> None:
    """Default weights sum to 1.0 across 7 categories."""
    assert len(DEFAULT_CATEGORY_WEIGHTS) == 7
    assert pytest.approx(sum(DEFAULT_CATEGORY_WEIGHTS.values())) == 1.0


def test_custom_category_weights() -> None:
    """Custom category weights overriding defaults are validated and accepted."""
    custom = {
        "security": 0.40,
        "quality": 0.20,
        "complexity": 0.10,
        "dependencies": 0.10,
        "documentation": 0.10,
        "structure": 0.05,
        "git": 0.05,
    }
    engine = HealthScoreEngine(weights=custom)
    assert engine.weights["security"] == 0.40


def test_invalid_weights_type_and_negative() -> None:
    """Non-numeric or negative weights raise ValueError."""
    with pytest.raises(ValueError, match="must be numeric"):
        HealthScoreEngine(weights={"security": "invalid"})  # type: ignore[dict-item]

    with pytest.raises(ValueError, match="cannot be negative"):
        HealthScoreEngine(weights={"security": -0.10})


def test_weight_sum_validation_raises() -> None:
    """Weights that do not sum to 1.0 raise ValueError."""
    with pytest.raises(ValueError, match="sum to 1.0"):
        HealthScoreEngine(weights={"security": 0.50})  # total != 1.0


# ---------------------------------------------------------------------------
# 7-13. Scoring Formulas
# ---------------------------------------------------------------------------


def test_security_severity_deductions() -> None:
    """Security score deducts based on exact severity deduction table."""
    sec = SecurityResult(
        python_files=5,
        issues=[
            Issue(
                category="security",
                severity=Severity.HIGH,
                code="B101",
                message="assert",
            ),
            Issue(
                category="security",
                severity=Severity.MEDIUM,
                code="B102",
                message="exec",
            ),
        ],
    )
    engine = HealthScoreEngine(security=sec)
    report = engine.calculate()
    # 100 - 15 (HIGH) - 7 (MEDIUM) = 78.0
    assert report.category_map["security"].score == 78.0


def test_quality_scoring_deductions() -> None:
    """Quality score deducts based on severity table for Quality-owned issues."""
    qual = QualityResult(
        python_files=5,
        issues=[
            Issue(
                category="quality",
                severity=Severity.HIGH,
                code="PYH001",
                message="long func",
            ),
            Issue(
                category="quality",
                severity=Severity.LOW,
                code="PYH003",
                message="todo",
            ),
        ],
    )
    engine = HealthScoreEngine(quality=qual)
    report = engine.calculate()
    # 100 - 15 (HIGH) - 2 (LOW) = 83.0
    assert report.category_map["quality"].score == 83.0


def test_complexity_scoring() -> None:
    """Complexity score combines Maintainability Index and high complexity findings."""
    comp = ComplexityResult(
        python_files=5,
        maintainability_index=85.0,
        high_complexity_findings=2,
    )
    engine = HealthScoreEngine(complexity=comp)
    report = engine.calculate()
    # 85 - (5 * 2) = 75.0
    assert report.category_map["complexity"].score == 75.0


def test_dependency_scoring() -> None:
    """Dependency score deducts for vulnerabilities, missing, and unused deps."""
    deps = DependencyResult(
        python_files=5,
        vulnerabilities_count=1,  # -15
        potentially_missing=["requests"],  # -10
        potentially_unused=["pytest"],  # -2
    )
    engine = HealthScoreEngine(dependencies=deps)
    report = engine.calculate()
    # 100 - 15 - 10 - 2 = 73.0
    assert report.category_map["dependencies"].score == 73.0


def test_documentation_scoring() -> None:
    """Documentation score uses docstring coverage and file deductions."""
    doc = DocumentationResult(
        files_analyzed=5,
        docstring_coverage=80.0,
        issues=[
            Issue(
                category="documentation",
                severity=Severity.LOW,
                code="PYH303",
                message="no changelog",
            ),
        ],
    )
    engine = HealthScoreEngine(documentation=doc)
    report = engine.calculate()
    # 80.0 - 5.0 = 75.0
    assert report.category_map["documentation"].score == 75.0


def test_structure_scoring(tmp_path: Path) -> None:
    """Structure score deducts for large files, empty dirs, duplicate files."""
    scan = ScanResult(
        project_path=tmp_path,
        total_files=10,
        python_files=5,
        directories=2,
        total_lines=500,
        total_size_bytes=50000,
        large_files=[tmp_path / "big.bin"],  # -5
        empty_directories=[tmp_path / "empty"],  # -3
        duplicate_files=[[tmp_path / "a.txt", tmp_path / "b.txt"]],  # -5
    )
    engine = HealthScoreEngine(structure=scan)
    report = engine.calculate()
    # 100 - 5 - 3 - 5 = 87.0
    assert report.category_map["structure"].score == 87.0


def test_git_scoring() -> None:
    """Git score deducts for missing .gitignore, large, and sensitive tracked files."""
    git_res = GitResult(
        repository_detected=True,
        gitignore_exists=False,  # -10
        large_tracked_files=[("big.zip", 20000000)],  # -10
        sensitive_tracked_files=[(".env")],  # -25
    )
    engine = HealthScoreEngine(git=git_res)
    report = engine.calculate()
    # 100 - 10 - 10 - 25 = 55.0
    assert report.category_map["git"].score == 55.0


# ---------------------------------------------------------------------------
# 14-17. Overall score, Unavailable categories, Clamping, Grades
# ---------------------------------------------------------------------------


def test_overall_weighted_score() -> None:
    """Overall score correctly aggregates available weighted categories."""
    engine = HealthScoreEngine(
        quality=QualityResult(python_files=1),
        security=SecurityResult(python_files=1),
    )
    report = engine.calculate()
    assert report.overall_score == 100.0
    assert report.grade == "Excellent"


def test_missing_unavailable_category() -> None:
    """Git category marked unavailable is excluded from denominator."""
    git_res = GitResult(repository_detected=False)
    engine = HealthScoreEngine(git=git_res)
    report = engine.calculate()
    assert report.category_map["git"].available is False
    assert report.overall_score == 100.0


def test_score_clamping() -> None:
    """Scores are strictly clamped between 0.0 and 100.0."""
    sec = SecurityResult(
        python_files=1,
        issues=[
            Issue(
                category="security",
                severity=Severity.CRITICAL,
                code="PYS001",
                message="c1",
            ),
            Issue(
                category="security",
                severity=Severity.CRITICAL,
                code="PYS002",
                message="c2",
            ),
            Issue(
                category="security",
                severity=Severity.CRITICAL,
                code="PYS003",
                message="c3",
            ),
            Issue(
                category="security",
                severity=Severity.CRITICAL,
                code="PYS004",
                message="c4",
            ),
        ],
    )
    engine = HealthScoreEngine(security=sec)
    report = engine.calculate()
    assert report.category_map["security"].score == 0.0


def test_grade_boundaries() -> None:
    """PyHealth Grade boundaries map correctly to score ranges."""
    assert HealthScoreEngine._get_grade(95.0) == "Excellent"
    assert HealthScoreEngine._get_grade(85.0) == "Good"
    assert HealthScoreEngine._get_grade(75.0) == "Fair"
    assert HealthScoreEngine._get_grade(60.0) == "Needs Improvement"
    assert HealthScoreEngine._get_grade(40.0) == "Poor"


# ---------------------------------------------------------------------------
# 18-22. Priority Ordering, Deduplication, Double-counting Protection
# ---------------------------------------------------------------------------


def test_priority_ordering() -> None:
    """Issues are deterministically ordered by severity, impact, weight, file/line."""
    qual = QualityResult(
        python_files=1,
        issues=[
            Issue(
                category="quality",
                severity=Severity.LOW,
                code="PYH003",
                message="todo",
                file="a.py",
                line=10,
            ),
            Issue(
                category="quality",
                severity=Severity.HIGH,
                code="PYH001",
                message="long",
                file="a.py",
                line=5,
            ),
        ],
    )
    sec = SecurityResult(
        python_files=1,
        issues=[
            Issue(
                category="security",
                severity=Severity.CRITICAL,
                code="PYS001",
                message="secret",
                file="b.py",
                line=1,
            ),
        ],
    )
    engine = HealthScoreEngine(quality=qual, security=sec)
    report = engine.calculate()
    assert report.priority_issues[0].code == "PYS001"
    assert report.priority_issues[1].code == "PYH001"


def test_top_n_priority_limit() -> None:
    """top_n_priorities parameter limits the returned list length."""
    sec = SecurityResult(
        python_files=1,
        issues=[
            Issue(
                category="security",
                severity=Severity.HIGH,
                code=f"PYS00{i}",
                message=f"m{i}",
            )
            for i in range(10)
        ],
    )
    engine = HealthScoreEngine(security=sec, top_n_priorities=3)
    report = engine.calculate()
    assert len(report.priority_issues) == 3


def test_recommendation_deduplication() -> None:
    """Duplicate issue recommendation strings are deduplicated."""
    sec = SecurityResult(
        python_files=1,
        issues=[
            Issue(
                category="security",
                severity=Severity.HIGH,
                code="PYS001",
                message="secret1",
                file="a.py",
            ),
            Issue(
                category="security",
                severity=Severity.HIGH,
                code="PYS002",
                message="secret2",
                file="b.py",
            ),
        ],
    )
    engine = HealthScoreEngine(security=sec)
    report = engine.calculate()
    assert len(report.recommendations) == 1
    assert "Remove exposed credentials" in report.recommendations[0]


def test_zero_secret_findings_no_credentials_recommendation() -> None:
    """Zero secret findings with non-secret Bandit findings (e.g. B101 assert)
    must NOT produce an 'exposed credentials' recommendation.
    """
    sec = SecurityResult(
        python_files=1,
        issues=[
            Issue(
                category="security",
                severity=Severity.LOW,
                code="B101",
                message="B101 — Use of assert statement",
                file="qr.py",
                line=12,
                tool="bandit",
                suggestion=(
                    "Avoid assert in production code; use explicit error handling."
                ),
            ),
        ],
        bandit_findings=1,
        secret_findings=0,
    )
    engine = HealthScoreEngine(security=sec)
    report = engine.calculate()

    # Recommendations must NOT claim exposed credentials when 0 secret findings exist
    for rec in report.recommendations:
        assert "exposed credentials" not in rec.lower()
        assert "remove exposed credentials" not in rec.lower()

    assert "Avoid assert in production code" in report.recommendations[0]


def test_real_secret_finding_credentials_recommendation() -> None:
    """Real secret finding produces 'Remove exposed credentials' recommendation."""
    sec = SecurityResult(
        python_files=1,
        issues=[
            Issue(
                category="security",
                severity=Severity.HIGH,
                code="PYS001",
                message="Potential hardcoded secret in variable 'API_KEY'",
                file="config.py",
                line=5,
                tool="pyhealth",
            ),
        ],
        bandit_findings=0,
        secret_findings=1,
    )
    engine = HealthScoreEngine(security=sec)
    report = engine.calculate()

    assert any("exposed credentials" in rec.lower() for rec in report.recommendations)


def test_duplicate_issue_protection() -> None:
    """Exact duplicate Issue instances are not processed twice."""
    same_issue = Issue(
        category="quality",
        severity=Severity.HIGH,
        code="PYH001",
        message="long func",
        file="a.py",
        line=5,
    )
    qual = QualityResult(python_files=1, issues=[same_issue, same_issue])
    engine = HealthScoreEngine(quality=qual)
    report = engine.calculate()
    assert len(report.priority_issues) == 1


def test_syntax_error_not_double_counted() -> None:
    """PYH005 syntax error is owned by Quality and does not penalize Security."""
    pyh005 = Issue(
        category="quality",
        severity=Severity.HIGH,
        code="PYH005",
        message="Syntax error",
    )
    qual = QualityResult(python_files=1, issues=[pyh005])
    sec = SecurityResult(python_files=1, issues=[])
    engine = HealthScoreEngine(quality=qual, security=sec)
    report = engine.calculate()
    assert report.category_map["quality"].score == 85.0
    assert report.category_map["security"].score == 100.0


# ---------------------------------------------------------------------------
# Refinement #10: Deterministic Fixtures Tests
# ---------------------------------------------------------------------------


def test_fixture_clean_project() -> None:
    """Clean project with no issues produces 100/100 score and Grade 'Excellent'."""
    engine = HealthScoreEngine(
        quality=QualityResult(python_files=1),
        security=SecurityResult(python_files=1),
        complexity=ComplexityResult(python_files=1, maintainability_index=100.0),
        dependencies=DependencyResult(python_files=1),
        documentation=DocumentationResult(
            files_analyzed=1,
            docstring_coverage=100.0,
            readme_exists=True,
            license_exists=True,
            changelog_exists=True,
            contributing_exists=True,
        ),
        git=GitResult(repository_detected=True, gitignore_exists=True),
    )
    report = engine.calculate()
    assert report.overall_score == 100.0
    assert report.grade == "Excellent"


def test_fixture_security_heavy_project() -> None:
    """Security-heavy project drops Security score; unrelated stay 100.0."""
    sec = SecurityResult(
        python_files=1,
        issues=[
            Issue(
                category="security",
                severity=Severity.CRITICAL,
                code="PYS001",
                message="Secret key exposed",
            ),
        ],
    )
    engine = HealthScoreEngine(
        quality=QualityResult(python_files=1),
        security=sec,
        documentation=DocumentationResult(
            files_analyzed=1,
            docstring_coverage=100.0,
            readme_exists=True,
            license_exists=True,
            changelog_exists=True,
            contributing_exists=True,
        ),
    )
    report = engine.calculate()
    assert report.category_map["security"].score == 70.0
    assert report.category_map["quality"].score == 100.0
    assert report.category_map["documentation"].score == 100.0


def test_fixture_dependency_vulnerability_project() -> None:
    """Vulnerable dependency reduces Dependency score ONLY, not Security."""
    deps = DependencyResult(
        python_files=1,
        vulnerabilities_count=1,
        issues=[
            Issue(
                category="dependencies",
                severity=Severity.HIGH,
                code="PYH203",
                message="Vulnerability in requests",
            ),
        ],
    )
    sec = SecurityResult(python_files=1, issues=[])
    engine = HealthScoreEngine(dependencies=deps, security=sec)
    report = engine.calculate()
    assert report.category_map["dependencies"].score == 85.0
    assert report.category_map["security"].score == 100.0


def test_fixture_no_git_project() -> None:
    """No-Git project reports Git as N/A and excludes Git weight."""
    git_res = GitResult(repository_detected=False)
    engine = HealthScoreEngine(
        quality=QualityResult(python_files=1),
        git=git_res,
    )
    report = engine.calculate()
    assert report.category_map["git"].available is False
    assert report.overall_score == 100.0


def test_fixture_invalid_configuration(tmp_path: Path) -> None:
    """Invalid pyproject.toml [tool.pyhealth.score] configuration raises ValueError."""
    bad_toml = tmp_path / "pyproject.toml"
    bad_toml.write_text("[tool.pyhealth.score]\nsecurity = 0.90\n", encoding="utf-8")
    with pytest.raises(ValueError, match="sum to 1.0"):
        HealthScoreEngine(config_path=bad_toml)


# ---------------------------------------------------------------------------
# 23-25. CLI integration & Regression checks
# ---------------------------------------------------------------------------


def test_cli_scan_command_with_health_summary(tmp_path: Path) -> None:
    """pyhealth scan includes HEALTH SCORE section."""
    res = runner.invoke(app, ["scan", str(tmp_path)])
    assert res.exit_code == 0
    assert "HEALTH SCORE" in res.output


def test_existing_analyzer_commands_still_works(tmp_path: Path) -> None:
    """Existing CLI analyzer commands continue working."""
    assert runner.invoke(app, ["docs", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["deps", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["quality", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["security", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["complexity", str(tmp_path)]).exit_code == 0
    assert runner.invoke(app, ["git", str(tmp_path)]).exit_code == 0


def test_version_remains_2_0_0() -> None:
    """Package version remains 2.0.0."""
    assert pyhealth.__version__ == "2.0.0"
