"""Data models for PyHealth scan results.

These dataclasses are intentionally kept independent of any display library
so that they can be consumed by CLI output, JSON serialisation, or future
report generators without modification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# ---------------------------------------------------------------------------
# Stage 2: Project Scanner model
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Aggregated results produced by :class:`~pyhealth.scanner.ProjectScanner`.

    Attributes:
        project_path: Root directory that was scanned.
        total_files: Total number of files found (all types).
        python_files: Number of ``.py`` files found.
        directories: Number of sub-directories found (excluding ignored ones).
        total_lines: Physical lines of code across all Python files.
        total_size_bytes: Combined size in bytes of every scanned file.
        large_files: Files whose size exceeds the configured threshold.
        empty_directories: Directories that contain no non-ignored entries.
        duplicate_files: Groups of files with identical byte content.
            Each inner list holds two or more :class:`~pathlib.Path` objects.
    """

    project_path: Path
    total_files: int
    python_files: int
    directories: int
    total_lines: int
    total_size_bytes: int
    large_files: list[Path] = field(default_factory=list)
    empty_directories: list[Path] = field(default_factory=list)
    duplicate_files: list[list[Path]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Stage 3: Code Quality models
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Issue severity level used by all PyHealth analysers."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Issue:
    """A single finding produced by any PyHealth analyser.

    Frozen so that issues can be safely stored in sets and used as dict keys.
    The model is display-library-independent; formatters live in the CLI layer.

    Attributes:
        category: Broad grouping (e.g. ``"quality"``, ``"security"``).
        severity: How serious the issue is.
        code: Short identifier such as ``"F401"`` or ``"PYH001"``.
        message: Human-readable description.
        file: Source file path, if applicable.
        line: 1-based line number, if applicable.
        column: 0-based column offset, if applicable.
        tool: Which tool produced the finding (e.g. ``"ruff"``, ``"pyhealth"``).
        suggestion: Optional remediation hint.
    """

    category: str
    severity: Severity
    code: str
    message: str
    file: str | None = None
    line: int | None = None
    column: int | None = None
    tool: str = "pyhealth"
    suggestion: str | None = None


@dataclass
class QualityResult:
    """Aggregated results from :class:`~pyhealth.analyzers.quality.QualityAnalyzer`.

    Attributes:
        python_files: Number of Python files that were analysed.
        issues: Every :class:`Issue` found across all checks.
        ruff_findings: Number of issues produced by Ruff.
        long_functions: Number of PYH001 (long function) findings.
        deep_nesting: Number of PYH002 (deep nesting) findings.
        todo_fixme_count: Number of PYH003 (TODO/FIXME) findings.
        duplicate_function_count: Number of PYH004 (duplicate function) findings.
    """

    python_files: int
    issues: list[Issue] = field(default_factory=list)
    ruff_findings: int = 0
    long_functions: int = 0
    deep_nesting: int = 0
    todo_fixme_count: int = 0
    duplicate_function_count: int = 0

    @property
    def total_issues(self) -> int:
        """Total number of issues found across all checks."""
        return len(self.issues)

    @property
    def total_findings(self) -> int:
        """Total number of issues/findings found across all checks."""
        return len(self.issues)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Number of issues per :class:`Severity` level, in definition order."""
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for issue in self.issues:
            counts[issue.severity] += 1
        return counts


# ---------------------------------------------------------------------------
# Stage 4: Security models
# ---------------------------------------------------------------------------


@dataclass
class SecurityResult:
    """Aggregated results from :class:`~pyhealth.analyzers.security.SecurityAnalyzer`.

    Attributes:
        python_files: Number of Python files that were analysed.
        issues: Every :class:`Issue` found across all checks.
        bandit_findings: Number of findings produced by Bandit.
        secret_findings: Number of native secret findings.
    """

    python_files: int
    issues: list[Issue] = field(default_factory=list)
    bandit_findings: int = 0
    secret_findings: int = 0

    @property
    def total_findings(self) -> int:
        """Total number of security issues/findings."""
        return len(self.issues)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Number of issues per :class:`Severity` level, in definition order."""
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for issue in self.issues:
            counts[issue.severity] += 1
        return counts


# ---------------------------------------------------------------------------
# Stage 5: Complexity models
# ---------------------------------------------------------------------------


@dataclass
class ComplexityResult:
    """Aggregated results from complexity analysis.

    Attributes:
        python_files: Number of Python files that were analysed.
        issues: Every :class:`Issue` found across all checks.
        functions_analyzed: Number of functions and methods analysed.
        classes_analyzed: Number of classes analysed.
        average_complexity: Average cyclomatic complexity across functions.
        max_complexity: Maximum cyclomatic complexity among all functions.
        maintainability_index: Project-wide Maintainability Index (0–100 scale).
        high_complexity_findings: Number of functions exceeding threshold.
    """

    python_files: int
    issues: list[Issue] = field(default_factory=list)
    functions_analyzed: int = 0
    classes_analyzed: int = 0
    average_complexity: float = 0.0
    max_complexity: int = 0
    maintainability_index: float = 100.0
    high_complexity_findings: int = 0

    @property
    def total_findings(self) -> int:
        """Total number of complexity issues/findings."""
        return len(self.issues)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Number of issues per :class:`Severity` level, in definition order."""
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for issue in self.issues:
            counts[issue.severity] += 1
        return counts


# ---------------------------------------------------------------------------
# Stage 6: Dependency models
# ---------------------------------------------------------------------------


@dataclass
class DependencyResult:
    """Aggregated results from dependency analysis.

    Attributes:
        python_files: Number of Python files analysed.
        issues: Every :class:`Issue` found across all dependency checks.
        declared_dependencies: Declared third-party dependencies (production).
        imported_packages: Imported third-party packages detected.
        potentially_unused: Declared packages not found in source imports.
        potentially_missing: Imported packages not found in declarations.
        installed_packages: Mapping of package name to installed version string.
        vulnerabilities_count: Number of vulnerability advisories reported.
    """

    python_files: int
    issues: list[Issue] = field(default_factory=list)
    declared_dependencies: list[str] = field(default_factory=list)
    imported_packages: list[str] = field(default_factory=list)
    potentially_unused: list[str] = field(default_factory=list)
    potentially_missing: list[str] = field(default_factory=list)
    installed_packages: dict[str, str] = field(default_factory=dict)
    vulnerabilities_count: int = 0

    @property
    def total_findings(self) -> int:
        """Total number of dependency issues/findings."""
        return len(self.issues)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Number of issues per :class:`Severity` level, in definition order."""
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for issue in self.issues:
            counts[issue.severity] += 1
        return counts


# ---------------------------------------------------------------------------
# Stage 7: Documentation models
# ---------------------------------------------------------------------------


@dataclass
class DocumentationResult:
    """Aggregated results from documentation analysis.

    Attributes:
        issues: Every :class:`Issue` found across all documentation checks.
        files_analyzed: Total Python files analyzed.
        public_modules: Number of public modules analyzed.
        public_classes: Number of public classes analyzed.
        public_functions: Number of public functions analyzed.
        documented_objects: Total public objects with docstrings.
        docstring_coverage: Docstring coverage percentage (0.0 to 100.0).
        readme_exists: Whether a README file was found.
        license_exists: Whether a LICENSE file was found.
        changelog_exists: Whether a CHANGELOG file was found.
        contributing_exists: Whether a CONTRIBUTING file was found.
    """

    issues: list[Issue] = field(default_factory=list)
    files_analyzed: int = 0
    public_modules: int = 0
    public_classes: int = 0
    public_functions: int = 0
    documented_objects: int = 0
    docstring_coverage: float = 100.0
    readme_exists: bool = False
    license_exists: bool = False
    changelog_exists: bool = False
    contributing_exists: bool = False

    @property
    def total_public_objects(self) -> int:
        """Total public objects counted for documentation analysis."""
        return self.public_modules + self.public_classes + self.public_functions

    @property
    def total_findings(self) -> int:
        """Total number of documentation issues/findings."""
        return len(self.issues)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Number of issues per :class:`Severity` level, in definition order."""
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for issue in self.issues:
            counts[issue.severity] += 1
        return counts


# ---------------------------------------------------------------------------
# Stage 8: Git Health models
# ---------------------------------------------------------------------------


@dataclass
class GitResult:
    """Aggregated results from Git health analysis.

    Attributes:
        repository_detected: Whether a Git repository was detected.
        gitignore_exists: Whether a .gitignore file exists.
        repo_root: Root directory of the Git repository, if detected.
        tracked_files_count: Number of tracked files in the analysis path.
        untracked_files_count: Number of untracked files in the analysis path.
        large_tracked_files: List of (relative_path_str, size_bytes) for tracked
            files >= 10 MiB.
        sensitive_tracked_files: List of relative path strings of sensitive
            tracked files.
        branch_name: Current Git branch name, if available.
        commit_count: Total commit count, if available.
        issues: Every :class:`Issue` found across all Git health checks.
    """

    repository_detected: bool = False
    gitignore_exists: bool = False
    repo_root: Path | None = None
    tracked_files_count: int = 0
    untracked_files_count: int = 0
    large_tracked_files: list[tuple[str, int]] = field(default_factory=list)
    sensitive_tracked_files: list[str] = field(default_factory=list)
    branch_name: str | None = None
    commit_count: int | None = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        """Total number of Git health issues/findings."""
        return len(self.issues)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Number of issues per :class:`Severity` level, in definition order."""
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for issue in self.issues:
            counts[issue.severity] += 1
        return counts


# ---------------------------------------------------------------------------
# Stage 9: Unified Health models
# ---------------------------------------------------------------------------


@dataclass
class CategoryScore:
    """Score breakdown for a single category."""

    name: str
    score: float
    weight: float
    available: bool = True


@dataclass
class HealthReport:
    """Aggregated health report produced by HealthScoreEngine.

    Attributes:
        overall_score: Weighted overall project health score (0.0 to 100.0).
        grade: PyHealth Grade string ("Excellent", "Good", "Fair", etc.).
        categories: List of CategoryScore instances.
        priority_issues: Ranked top priority issues.
        recommendations: Actionable recommendations derived from priority issues.
    """

    overall_score: float
    grade: str
    categories: list[CategoryScore]
    priority_issues: list[Issue] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def category_map(self) -> dict[str, CategoryScore]:
        """Map of category name to CategoryScore."""
        return {c.name: c for c in self.categories}


# ---------------------------------------------------------------------------
# Stage 10: Unified Report model
# ---------------------------------------------------------------------------


@dataclass
class ProjectReport:
    """Complete aggregated project report holding all analyzer results.

    Attributes:
        project_path: Path to the scanned project directory.
        scan: ScanResult from ProjectScanner.
        quality: QualityResult from QualityAnalyzer.
        security: SecurityResult from SecurityAnalyzer.
        complexity: ComplexityResult from ComplexityAnalyzer.
        dependencies: DependencyResult from DependencyAnalyzer.
        documentation: DocumentationResult from DocumentationAnalyzer.
        git: GitResult from GitAnalyzer.
        health: HealthReport from HealthScoreEngine.
    """

    project_path: Path
    scan: ScanResult | None = None
    quality: QualityResult | None = None
    security: SecurityResult | None = None
    complexity: ComplexityResult | None = None
    dependencies: DependencyResult | None = None
    documentation: DocumentationResult | None = None
    git: GitResult | None = None
    health: HealthReport | None = None

    def all_issues(self) -> list[Issue]:
        """Return all collected issues, deterministically ordered."""
        issues: list[Issue] = []
        seen_keys: set[tuple[str, str, int, str]] = set()

        def collect(issue_list: list[Issue]) -> None:
            for issue in issue_list:
                key = (
                    issue.code,
                    issue.file or "",
                    issue.line or 0,
                    issue.message,
                )
                if key not in seen_keys:
                    seen_keys.add(key)
                    issues.append(issue)

        if self.security:
            collect(self.security.issues)
        if self.quality:
            collect(self.quality.issues)
        if self.complexity:
            collect(self.complexity.issues)
        if self.dependencies:
            collect(self.dependencies.issues)
        if self.documentation:
            collect(self.documentation.issues)
        if self.git and self.git.repository_detected:
            collect(self.git.issues)

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        issues.sort(
            key=lambda i: (
                sev_order.get(str(i.severity).lower(), 99),
                i.category or "",
                i.file or "",
                i.line or 0,
                i.code or "",
            )
        )
        return issues