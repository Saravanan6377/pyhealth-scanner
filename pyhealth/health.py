"""Unified Health Score Engine for PyHealth.

Calculates category scores, weighted overall project health score, PyHealth grade,
priority issue rankings, and deduplicated recommendations across all analyzer results.
"""

from __future__ import annotations

import math
from pathlib import Path

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

# Python 3.11+ tomllib, with fallback to tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


DEFAULT_CATEGORY_WEIGHTS: dict[str, float] = {
    "security": 0.30,
    "quality": 0.20,
    "complexity": 0.15,
    "dependencies": 0.15,
    "documentation": 0.10,
    "structure": 0.05,
    "git": 0.05,
}

SEVERITY_DEDUCTIONS: dict[Severity, float] = {
    Severity.CRITICAL: 30.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 7.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_RECOMMENDATION_MAPPINGS: dict[str, str] = {
    "PYH101": "Refactor highly complex functions.",
    "PYH201": "Verify whether declared dependencies are required.",
    "PYH202": "Declare missing third-party dependencies.",
    "PYH203": "Upgrade vulnerable dependencies.",
    "PYH301": "Add a comprehensive README file.",
    "PYH302": "Add a project license.",
    "PYH303": "Add a CHANGELOG file.",
    "PYH304": "Add a CONTRIBUTING guide.",
    "PYH305": "Add missing public API docstrings.",
    "PYH401": "Add a .gitignore file.",
    "PYH402": "Use Git LFS for large tracked files.",
    "PYH403": (
        "Remove sensitive files from Git tracking and rotate exposed credentials."
    ),
}


_SECRET_ISSUE_CODES: set[str] = {"B105", "B106", "B107"}


def _get_issue_recommendation(issue: Issue) -> str:
    """Return an appropriate recommendation string for a given Issue."""
    rec = _RECOMMENDATION_MAPPINGS.get(issue.code)
    if rec:
        return rec

    if issue.code.startswith("PYS") or issue.code in _SECRET_ISSUE_CODES:
        return "Remove exposed credentials from source code."

    if issue.suggestion:
        return issue.suggestion

    if issue.category == "security":
        return "Fix security findings and potential vulnerabilities."

    if issue.category == "quality":
        return "Fix code quality findings and lint violations."

    return issue.message


class HealthScoreEngine:
    """Calculates project health score, category scores, and priority recommendations.

    Args:
        quality: Result from QualityAnalyzer.
        security: Result from SecurityAnalyzer.
        complexity: Result from ComplexityAnalyzer.
        dependencies: Result from DependencyAnalyzer.
        documentation: Result from DocumentationAnalyzer.
        structure: Result from ProjectScanner.
        git: Result from GitAnalyzer.
        weights: Optional custom category weights dictionary.
        config_path: Optional path to pyproject.toml configuration file.
        top_n_priorities: Number of top priority issues to return (default: 5).
    """

    def __init__(
        self,
        quality: QualityResult | None = None,
        security: SecurityResult | None = None,
        complexity: ComplexityResult | None = None,
        dependencies: DependencyResult | None = None,
        documentation: DocumentationResult | None = None,
        structure: ScanResult | None = None,
        git: GitResult | None = None,
        weights: dict[str, float] | None = None,
        config_path: Path | None = None,
        top_n_priorities: int = 5,
    ) -> None:
        self.quality = quality
        self.security = security
        self.complexity = complexity
        self.dependencies = dependencies
        self.documentation = documentation
        self.structure = structure
        self.git = git
        self.top_n_priorities = top_n_priorities

        # Determine weights
        if weights is not None:
            self.weights = self._validate_weights(weights)
        elif config_path is not None and config_path.is_file():
            self.weights = self._load_and_validate_config(config_path)
        else:
            self.weights = dict(DEFAULT_CATEGORY_WEIGHTS)

    def calculate(self) -> HealthReport:
        """Calculate and return the aggregated HealthReport."""
        categories: list[CategoryScore] = []

        # 1. Security
        sec_score = self._score_security()
        categories.append(
            CategoryScore(
                name="security",
                score=sec_score,
                weight=self.weights["security"],
                available=self.security is not None,
            )
        )

        # 2. Quality
        qual_score = self._score_quality()
        categories.append(
            CategoryScore(
                name="quality",
                score=qual_score,
                weight=self.weights["quality"],
                available=self.quality is not None,
            )
        )

        # 3. Complexity
        comp_score = self._score_complexity()
        categories.append(
            CategoryScore(
                name="complexity",
                score=comp_score,
                weight=self.weights["complexity"],
                available=self.complexity is not None,
            )
        )

        # 4. Dependencies
        dep_score = self._score_dependencies()
        categories.append(
            CategoryScore(
                name="dependencies",
                score=dep_score,
                weight=self.weights["dependencies"],
                available=self.dependencies is not None,
            )
        )

        # 5. Documentation
        doc_score = self._score_documentation()
        categories.append(
            CategoryScore(
                name="documentation",
                score=doc_score,
                weight=self.weights["documentation"],
                available=self.documentation is not None,
            )
        )

        # 6. Structure
        struct_score = self._score_structure()
        categories.append(
            CategoryScore(
                name="structure",
                score=struct_score,
                weight=self.weights["structure"],
                available=self.structure is not None,
            )
        )

        # 7. Git
        git_score, git_avail = self._score_git()
        categories.append(
            CategoryScore(
                name="git",
                score=git_score,
                weight=self.weights["git"],
                available=git_avail,
            )
        )

        # Overall score calculation
        available_categories = [c for c in categories if c.available]
        if available_categories:
            total_avail_weight = sum(c.weight for c in available_categories)
            if total_avail_weight > 0:
                weighted_sum = sum(
                    c.score * c.weight for c in available_categories
                )
                overall_score = weighted_sum / total_avail_weight
            else:
                overall_score = 100.0
        else:
            overall_score = 100.0

        overall_score = self._clamp(overall_score)
        grade = self._get_grade(overall_score)

        # Priority issues & Recommendations
        priority_issues, recommendations = self._get_priorities_and_recommendations()

        return HealthReport(
            overall_score=overall_score,
            grade=grade,
            categories=categories,
            priority_issues=priority_issues,
            recommendations=recommendations,
        )

    def _score_security(self) -> float:
        if self.security is None:
            return 100.0
        base = 100.0
        deductions = sum(
            SEVERITY_DEDUCTIONS.get(issue.severity, 0.0)
            for issue in self.security.issues
        )
        return self._clamp(base - deductions)

    def _score_quality(self) -> float:
        if self.quality is None:
            return 100.0
        base = 100.0
        deductions = sum(
            SEVERITY_DEDUCTIONS.get(issue.severity, 0.0)
            for issue in self.quality.issues
        )
        return self._clamp(base - deductions)

    def _score_complexity(self) -> float:
        if self.complexity is None:
            return 100.0
        mi = self.complexity.maintainability_index
        high_comp_count = self.complexity.high_complexity_findings
        score = mi - (5.0 * high_comp_count)
        return self._clamp(score)

    def _score_dependencies(self) -> float:
        if self.dependencies is None:
            return 100.0
        base = 100.0
        vuln_count = self.dependencies.vulnerabilities_count
        missing_count = len(self.dependencies.potentially_missing)
        unused_count = len(self.dependencies.potentially_unused)
        deductions = (15.0 * vuln_count) + (10.0 * missing_count) + (2.0 * unused_count)
        return self._clamp(base - deductions)

    def _score_documentation(self) -> float:
        if self.documentation is None:
            return 100.0
        cov = self.documentation.docstring_coverage
        file_deductions = 0.0
        for issue in self.documentation.issues:
            if issue.code == "PYH301":
                file_deductions += (
                    8.0 if issue.severity == Severity.MEDIUM else 15.0
                )
            elif issue.code == "PYH302":
                file_deductions += 15.0
            elif issue.code == "PYH303":
                file_deductions += 5.0
            elif issue.code == "PYH304":
                file_deductions += 2.0
        return self._clamp(cov - file_deductions)

    def _score_structure(self) -> float:
        if self.structure is None:
            return 100.0
        base = 100.0
        large_files_count = len(self.structure.large_files)
        empty_dirs_count = len(self.structure.empty_directories)
        duplicate_groups_count = len(self.structure.duplicate_files)
        deductions = (
            (5.0 * large_files_count)
            + (3.0 * empty_dirs_count)
            + (5.0 * duplicate_groups_count)
        )
        return self._clamp(base - deductions)

    def _score_git(self) -> tuple[float, bool]:
        if self.git is None or not self.git.repository_detected:
            return 100.0, False
        base = 100.0
        deductions = 0.0
        if not self.git.gitignore_exists:
            deductions += 10.0
        deductions += 10.0 * len(self.git.large_tracked_files)
        deductions += 25.0 * len(self.git.sensitive_tracked_files)
        return self._clamp(base - deductions), True

    def _get_priorities_and_recommendations(
        self,
    ) -> tuple[list[Issue], list[str]]:
        """Collect, rank, limit priority issues and build recommendations."""
        all_issues: list[Issue] = []
        unique_keys: set[tuple[str, str, int, str]] = set()

        def add_issues(issues_list: list[Issue]) -> None:
            for issue in issues_list:
                key = (
                    issue.code,
                    issue.file or "",
                    issue.line or 0,
                    issue.message,
                )
                if key not in unique_keys:
                    unique_keys.add(key)
                    all_issues.append(issue)

        if self.security:
            add_issues(self.security.issues)
        if self.quality:
            add_issues(self.quality.issues)
        if self.complexity:
            add_issues(self.complexity.issues)
        if self.dependencies:
            add_issues(self.dependencies.issues)
        if self.documentation:
            add_issues(self.documentation.issues)
        if self.git and self.git.repository_detected:
            add_issues(self.git.issues)

        # Sort key: (1) Severity order, (2) Score impact estimate,
        # (3) Category weight, (4) File/line/code tie-breaker
        def issue_sort_key(issue: Issue) -> tuple[int, float, float, str, int, str]:
            sev_rank = SEVERITY_ORDER.get(issue.severity, 99)
            impact = SEVERITY_DEDUCTIONS.get(issue.severity, 0.0)
            cat_weight = self.weights.get(issue.category, 0.05)
            file_key = issue.file or ""
            line_key = issue.line or 0
            code_key = issue.code or ""
            return (sev_rank, -impact, -cat_weight, file_key, line_key, code_key)

        all_issues.sort(key=issue_sort_key)
        top_issues = all_issues[: self.top_n_priorities]

        # Recommendations generation
        recommendations: list[str] = []
        seen_recs: set[str] = set()

        for issue in top_issues:
            rec = _get_issue_recommendation(issue)
            if rec and rec not in seen_recs:
                seen_recs.add(rec)
                recommendations.append(rec)

        return top_issues, recommendations

    @staticmethod
    def _clamp(val: float) -> float:
        return max(0.0, min(100.0, val))

    @staticmethod
    def _get_grade(score: float) -> str:
        if score >= 90.0:
            return "Excellent"
        if score >= 80.0:
            return "Good"
        if score >= 70.0:
            return "Fair"
        if score >= 50.0:
            return "Needs Improvement"
        return "Poor"

    @classmethod
    def _validate_weights(cls, weights: dict[str, float]) -> dict[str, float]:
        """Validate custom weights dictionary."""
        if not isinstance(weights, dict):
            raise ValueError("Weights must be a dictionary.")

        for key in weights:
            if key not in DEFAULT_CATEGORY_WEIGHTS:
                raise ValueError(f"Unknown category in weights: '{key}'")

        full_weights = dict(DEFAULT_CATEGORY_WEIGHTS)
        full_weights.update(weights)

        for key, val in full_weights.items():
            if not isinstance(val, (int, float)):
                raise ValueError(f"Weight for category '{key}' must be numeric.")
            if val < 0.0:
                raise ValueError(f"Weight for category '{key}' cannot be negative.")

        total = sum(full_weights.values())
        if not math.isclose(total, 1.0, abs_tol=1e-4):
            raise ValueError(
                f"Total category weights must sum to 1.0 (got {total:.4f})."
            )

        return full_weights

    @classmethod
    def _load_and_validate_config(cls, config_path: Path) -> dict[str, float]:
        """Load and validate [tool.pyhealth.score] from pyproject.toml."""
        if tomllib is None:
            return dict(DEFAULT_CATEGORY_WEIGHTS)

        try:
            content = config_path.read_text(encoding="utf-8", errors="replace")
            data = tomllib.loads(content)
        except Exception as exc:
            raise ValueError(f"Could not parse pyproject.toml: {exc}") from exc

        tool_sec = data.get("tool", {})
        if not isinstance(tool_sec, dict):
            return dict(DEFAULT_CATEGORY_WEIGHTS)

        pyhealth_sec = tool_sec.get("pyhealth", {})
        if not isinstance(pyhealth_sec, dict):
            return dict(DEFAULT_CATEGORY_WEIGHTS)

        score_cfg = pyhealth_sec.get("score", {})
        if not score_cfg:
            return dict(DEFAULT_CATEGORY_WEIGHTS)

        if not isinstance(score_cfg, dict):
            raise ValueError("[tool.pyhealth.score] must be a table/dictionary.")

        return cls._validate_weights(score_cfg)
